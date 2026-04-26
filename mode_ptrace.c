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
			/* 0x80 not set: We are not handling a syscall. */

			if (ptrace(PTRACE_SETOPTIONS, pid, NULL,
				   PTRACE_O_TRACESYSGOOD) < 0)
				err(1, "ptrace(SETOPTIONS)");
		} else if (WSTOPSIG(wstatus) == (SIGTRAP|0x80)) {
			struct user_regs_struct regs = {};
			if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
				err(1, "ptrace(GETREGS)");

#ifdef __x86_64__
#define UREG(X) regs.r##X
#define rorig_ax orig_rax
#else
#define UREG(X) regs.e##X
#define eorig_ax orig_eax
#endif
			UREG(ax) = syscall_dispatch(UREG(orig_ax),
						    (syscall_args_t) {
							UREG(bx),
							UREG(cx),
							UREG(dx),
						    });

			if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0)
				err(1, "ptrace(SETREGS)");
		} else if (WSTOPSIG(wstatus) == SIGBUS ||
			   WSTOPSIG(wstatus) == SIGFPE ||
			   WSTOPSIG(wstatus) == SIGILL ||
			   WSTOPSIG(wstatus) == SIGSEGV ||
			   WSTOPSIG(wstatus) == SIGTRAP) {

			if (config.coredump) {
				struct user_regs_struct regs = {};
				if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
					err(1, "ptrace(GETREGS)");

				coredump_write(&(struct user_regs_struct_i386) {
						.ebx = UREG(bx),
						.ecx = UREG(cx),
						.edx = UREG(dx),
						.esi = UREG(si),
						.edi = UREG(di),
						.ebp = UREG(bp),
						.eax = UREG(ax),
						.eip = UREG(ip),
						.esp = UREG(sp),
						.eflags = regs.eflags,
						.orig_eax = UREG(orig_ax),
						});
			} else {
				fprintf(stderr, "Fatal signal %d\n",
					WSTOPSIG(wstatus));
			}
			if (kill(pid, 9) < 0)
				err(1, "kill");
			continue;
		} else {
			errx(1, "waitpid: unsupported signal");
		}

		if (ptrace(PTRACE_SYSEMU, pid, 0, 0) < 0)
			err(1, "ptrace(SYSEMU)");
	}
	err(1, "waitpid");
}

DEFINE_MODE(ptrace, k_thread_ptrace)
