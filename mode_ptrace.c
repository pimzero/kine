#include <err.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "kine.h"
#include "coredump.h"

static int ptrace_interrupted;

static void ptrace_sa_handler(int signum) {
	ptrace_interrupted = signum;
}

static void set_interrupt_sighandlers(void (*handler)(int)) {
	const int sigs[] = { SIGTERM, SIGHUP, SIGINT, SIGQUIT, SIGPIPE, };

	for (size_t i = 0; i < ARRSZE(sigs); i++) {
		if (sigaction(sigs[i], &(struct sigaction) {
				.sa_handler = handler,
			      }, NULL) < 0)
			err(1, "sigaction");
	}
}

__attribute((noreturn))
static void ptrace_interrupted_reraise(void) {
	set_interrupt_sighandlers(SIG_DFL);

	raise(ptrace_interrupted);

	errx(1, "ptrace_interrupted_reraise");
}

#ifdef __x86_64__
#define REG(X) regs.r##X
#define rorig_ax orig_rax
#else
#define REG(X) regs.e##X
#define eorig_ax orig_eax
#endif

static void handle_syscall(pid_t pid) {
	struct user_regs_struct regs = {};
	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
		err(1, "ptrace(GETREGS)");

	REG(ax) = syscall_dispatch(REG(orig_ax), REG(bx), REG(cx), REG(dx));

	if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0)
		err(1, "ptrace(SETREGS)");
}

static void handle_exception(pid_t pid, int sig) {
	if (config.coredump) {
		struct user_regs_struct regs = {};
		if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
			err(1, "ptrace(GETREGS)");

		coredump_write(&(struct user_regs_struct_i386) {
				.ebx = REG(bx),
				.ecx = REG(cx),
				.edx = REG(dx),
				.esi = REG(si),
				.edi = REG(di),
				.ebp = REG(bp),
				.eax = REG(ax),
				.eip = REG(ip),
				.esp = REG(sp),
				.eflags = regs.eflags,
				.orig_eax = REG(orig_ax),
				});
	}
	fprintf(stderr, "Fatal signal %d\n", sig);
	if (kill(pid, 9) < 0)
		err(1, "kill");
}

static void* k_thread_ptrace(void* entry) {
	k_prepare();

	pid_t pid = fork();
	if (!pid) {
		if (ptrace(PTRACE_TRACEME) < 0)
			err(1, "ptrace(PTRACE_TRACEME)");

		if (raise(SIGSTOP) < 0)
			err(1, "raise(SIGSTOP)");

		k_start(entry);
	}

	set_interrupt_sighandlers(ptrace_sa_handler);

	int wstatus;
	while (waitpid(pid, &wstatus, __WALL) >= 0) {
		if (ptrace_interrupted) {
			if (kill(pid, 9) < 0)
				err(1, "kill");
			ptrace_interrupted_reraise();
		}

		if (!WIFSTOPPED(wstatus)) {
			warnx("waitpid: unsupported");
			continue;
		}

		if (WSTOPSIG(wstatus) == SIGSTOP) {
			if (ptrace(PTRACE_SETOPTIONS, pid, NULL,
				   PTRACE_O_TRACESYSGOOD) < 0)
				err(1, "ptrace(SETOPTIONS)");
		} else if (WSTOPSIG(wstatus) == (SIGTRAP|0x80)) {
			handle_syscall(pid);
		} else if (WSTOPSIG(wstatus) == SIGBUS ||
			   WSTOPSIG(wstatus) == SIGFPE ||
			   WSTOPSIG(wstatus) == SIGILL ||
			   WSTOPSIG(wstatus) == SIGSEGV ||
			   WSTOPSIG(wstatus) == SIGTRAP) {
			handle_exception(pid, WSTOPSIG(wstatus));
			continue;
		} else {
			errx(1, "waitpid: unsupported signal %d",
			     WSTOPSIG(wstatus));
		}

		if (ptrace(PTRACE_SYSEMU, pid, 0, 0) < 0)
			err(1, "ptrace(SYSEMU)");
	}
	err(1, "waitpid");
}

DEFINE_MODE(ptrace, k_thread_ptrace)
