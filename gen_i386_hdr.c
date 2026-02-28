#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/time.h>
#include <limits.h>
#include <sys/user.h>
#include <sys/procfs.h>

#ifndef typeof
#define typeof(Value) __typeof__(Value)
#endif

#define IS_SIGNED(Val) ((typeof(Val))(-1) < 0)

#define FIELD(Member) do { \
	assert(offset <= offsetof(typeof(val), Member)); \
	offset = offsetof(typeof(val), Member); \
	printf("\t%sint%d_t " #Member ";\n", IS_SIGNED(val.Member) ? "" : "u", \
	       sizeof(val.Member) * CHAR_BIT); \
} while (0)

#define FIELD_T(Type, Member) do { \
	assert(offset <= offsetof(typeof(val), Member)); \
	offset = offsetof(typeof(val), Member); \
	assert(__builtin_types_compatible_p(typeof(val.Member), Type)); \
	printf("\t" #Type "_i386 " #Member ";\n"); \
} while (0)

#define STRUCT(Type, Fields) do {\
	struct Type val; \
	unsigned offset = 0; \
	printf("struct " #Type "_i386 {\n"); \
	Fields \
	printf("};\n"); \
	printf("_Static_assert(sizeof(struct " #Type "_i386) == %d, "");\n\n", sizeof(val)); \
} while (0)

static void do_user_regs_struct(void)
{
	STRUCT(user_regs_struct,
	       FIELD(ebx);
	       FIELD(ecx);
	       FIELD(edx);
	       FIELD(esi);
	       FIELD(edi);
	       FIELD(ebp);
	       FIELD(eax);
	       FIELD(xds);
	       FIELD(xes);
	       FIELD(xfs);
	       FIELD(xgs);
	       FIELD(orig_eax);
	       FIELD(eip);
	       FIELD(xcs);
	       FIELD(eflags);
	       FIELD(esp);
	       FIELD(xss);
	);
}

static void do_elf_prstatus(void)
{
	STRUCT(elf_prstatus,
	       /* We don't need to generate elf_siginfo_i386, it is the same for
		* x86_64.
		*/
	       printf("\tstruct elf_siginfo pr_info;\n");
	       FIELD(pr_cursig);
	       FIELD(pr_sigpend);
	       FIELD(pr_sighold);
	       FIELD(pr_pid);
	       FIELD(pr_ppid);
	       FIELD(pr_pgrp);
	       FIELD(pr_sid);
	       FIELD_T(struct timeval, pr_utime);
	       FIELD_T(struct timeval, pr_stime);
	       FIELD_T(struct timeval, pr_cutime);
	       FIELD_T(struct timeval, pr_cstime);
	       FIELD_T(elf_gregset_t, pr_reg);
	       FIELD(pr_fpvalid);
	      );
}

static void do_timeval(void)
{
	STRUCT(timeval,
	       FIELD(tv_sec);
	       FIELD(tv_usec);
	      );
}

int main() {
	printf("#ifndef I386_GEN_H\n"
	       "#define I386_GEN_H\n"
	       "\n"
	       "#include <stddef.h>\n"
	       "\n");

	do_timeval();
	do_user_regs_struct();
	printf("#define ELF_NGREG_I386 (sizeof (struct user_regs_struct_i386) / \\\n"
	       "\tsizeof((struct user_regs_struct_i386){}.eax))\n");
	printf("typedef uint32_t elf_gregset_t_i386[ELF_NGREG_I386];\n\n");
	do_elf_prstatus();

	printf("#endif /* I386_GEN_H */\n");
}
