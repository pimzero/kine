#include <asm/prctl.h>
#include <err.h>
#include <signal.h>
#include <stdlib.h>
#include <syscall.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "kine.h"

#ifndef PR_SET_SYSCALL_USER_DISPATCH
#define PR_SET_SYSCALL_USER_DISPATCH 59
#endif
#ifndef PR_SYS_DISPATCH_ON
#define PR_SYS_DISPATCH_ON 1
#endif
#ifndef HWCAP2_FSGSBASE
#define HWCAP2_FSGSBASE        (1 << 1)
#endif
#ifndef SYS_USER_DISPATCH
#define SYS_USER_DISPATCH 2
#endif

#if __x86_64__
static unsigned long k_thread_fs;

static int arch_prctl(int op, unsigned long* addr) {
	return syscall(SYS_arch_prctl, op, addr);
}

static int supports_fsgsbase(void) {
	return !!(getauxval(AT_HWCAP2) & HWCAP2_FSGSBASE);
}
#endif

static uint16_t get_cs(const ucontext_t* ctx) {
#if __x86_64__
	return ctx->uc_mcontext.gregs[REG_CSGSFS] & 0xffff;
#else
	return ctx->uc_mcontext.gregs[REG_CS];
#endif
}

#ifdef __x86_64__
#define R(R) "%r"#R
#else
#define R(R) "%e"#R
#endif

#define MAKE_SIGNAL_HANDLERS_ASM(Name, Prepare)		\
void sigsys_##Name(int sig, siginfo_t *info, void *ucontext);	\
void coredump_##Name(int sig, siginfo_t *info, void *ucontext);	\
							\
__asm__(						\
".pushsection .text\n"					\
"sigsys_" #Name ":\n\t"					\
"push " R(bp) "\n\t"					\
"mov " R(sp) ", " R(bp) "\n\t"				\
Prepare							\
"call sigsys_handler\n\t"				\
"leave\n\t"						\
"ret\n"							\
".size sigsys_" #Name ", .-sigsys_" #Name "\n"		\
"\n"							\
"coredump_" #Name ":\n\t"				\
"push " R(bp) "\n\t"					\
"mov " R(sp) ", " R(bp) "\n\t"				\
Prepare							\
"call coredump_handler\n\t"				\
"leave\n\t"						\
"ret\n"							\
".size coredump_" #Name ", .-coredump_" #Name "\n"	\
".popsection\n"						\
)

#ifdef __x86_64__

MAKE_SIGNAL_HANDLERS_ASM(handler_asm,
"push %rdi\n\t"
"push %rsi\n\t"
"push %rdx\n\t"

"mov $" XSTR(SYS_arch_prctl) ", %rax\n\t"
"mov $" XSTR(ARCH_SET_FS) ", %rdi\n\t"
"mov k_thread_fs(%rip), %rsi\n\t"
"syscall\n\t"

"pop %rsi\n\t" /* ucontext */
"pop %rdi\n\t" /* siginfo */
"add $8, %rsp\n\t");

MAKE_SIGNAL_HANDLERS_ASM(handler_asm_fsgsbase,
"mov k_thread_fs(%rip), %rdi\n\t"
"wrfsbase %rdi\n\t"
"mov %rsi, %rdi\n\t"
"mov %rdx, %rsi\n\t");

#define GET_SIGACTION(Kind) (supports_fsgsbase() ? Kind##_handler_asm_fsgsbase : Kind##_handler_asm)

#else

MAKE_SIGNAL_HANDLERS_ASM(handler_asm,
"mov $0, %bx\n\t"
"mov %bx, %fs\n\t"
"mov $" XSTR(SEG_REG(LINUX_GS, GDT, 3)) ", %bx\n\t"
"mov %bx, %gs\n\t"

"push 16(%ebp)\n\t" /* ctx */
"push 12(%ebp)\n\t" /* siginfo */);

#define GET_SIGACTION(Kind) Kind##_handler_asm

#endif

static void set_sigaction_on_stack(int sig, void (*f)(int, siginfo_t*, void*)) {
	struct sigaction sa = {
		.sa_sigaction = f,
		.sa_flags = SA_SIGINFO|SA_ONSTACK,
	};
	if (sigaction(sig, &sa, NULL) < 0)
		err(1, "sigaction");
}

static void k_setup_sighandler(void) {
	stack_t ss = {
		.ss_sp = malloc(SIGSTKSZ),
		.ss_size = SIGSTKSZ,
		.ss_flags = 0
	};
	if (!ss.ss_sp)
		err(1, "malloc");

	if (sigaltstack(&ss, NULL) < 0)
		err(1, "sigaltstack");

	set_sigaction_on_stack(SIGSYS, GET_SIGACTION(sigsys));
}

__attribute__ ((used))
static void sigsys_handler(siginfo_t* siginfo, struct ucontext_t* ctx) {
	if (siginfo->si_code != SYS_USER_DISPATCH)
		return;

#ifdef __x86_64__
#define REG(X) REG_R##X
#else
#define REG(X) REG_E##X
#endif
	syscall_args_t args = {
		ctx->uc_mcontext.gregs[REG(BX)],
		ctx->uc_mcontext.gregs[REG(CX)],
		ctx->uc_mcontext.gregs[REG(DX)],
	};

	ctx->uc_mcontext.gregs[REG(AX)] =
		syscall_dispatch(siginfo->si_syscall, args);
}

static int set_syscall_user_dispatch(void* start, void* end) {
	return prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON, start,
		     end, NULL);
}

__attribute__ ((used))
static void coredump_handler(siginfo_t *si, void *ucontext) {
	ucontext_t *ctx = ucontext;

	if (get_cs(ctx) != SEG_REG(CODE, LDT, 3)) {
		struct sigaction sa = {
			.sa_handler = SIG_DFL,
		};
		if (sigaction(si->si_signo, &sa, NULL) < 0)
			err(1, "sigaction(SIG_DFL)");

		return;
	}

	struct user_regs_struct_i386 regs = {
		.ebx = ctx->uc_mcontext.gregs[REG(BX)],
		.ecx = ctx->uc_mcontext.gregs[REG(CX)],
		.edx = ctx->uc_mcontext.gregs[REG(DX)],
		.esi = ctx->uc_mcontext.gregs[REG(SI)],
		.edi = ctx->uc_mcontext.gregs[REG(DI)],
		.ebp = ctx->uc_mcontext.gregs[REG(BP)],
		.eax = ctx->uc_mcontext.gregs[REG(AX)],
		.eip = ctx->uc_mcontext.gregs[REG(IP)],
		.esp = ctx->uc_mcontext.gregs[REG(SP)],
		.eflags = ctx->uc_mcontext.gregs[REG_EFL],
		.orig_eax = ctx->uc_mcontext.gregs[REG(AX)],
	};
	coredump_write(&regs);

	const char core_dumped_log[] = "Core dumped.\n";
	write(2, core_dumped_log, sizeof(core_dumped_log) - 1);
	_Exit(1);
}

static void setup_coredump_sighandlers(void) {
	const int sigs[] = { SIGBUS, SIGFPE, SIGILL, SIGSEGV, SIGTRAP, };

	for (size_t i = 0; i < ARRSZE(sigs); i++)
		set_sigaction_on_stack(sigs[i], GET_SIGACTION(coredump));
}

static int k_thread_syscall_user_dispatch_ex(entry_t entry, int probe) {
	if (set_syscall_user_dispatch((char*)config.base + config.limit,
				      (void*)~(0x1ULL<<63)) < 0) {
		if (probe)
			return -1;
		err(1, "set_syscall_user_dispatch");
	}

	if (config.coredump)
		setup_coredump_sighandlers();

	k_setup_sighandler();

#if __x86_64__
	if (arch_prctl(ARCH_GET_FS, &k_thread_fs) < 0)
		err(1, "arch_prctl(ARCH_GET_FS)");
#endif

	k_prepare();
	k_start(entry);
}

static void* k_thread_syscall_user_dispatch(void* entry) {
	k_thread_syscall_user_dispatch_ex(entry, 0);
	errx(1, "k_thread_syscall_user_dispatch_ex");
}

DEFINE_MODE(syscall_user_dispatch, k_thread_syscall_user_dispatch);
