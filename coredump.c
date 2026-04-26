#include <elf.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>
#include <stdio.h>

#include "kine.h"
#include "coredump.h"

#ifndef typeof
#define typeof(Value) __typeof__(Value)
#endif

#define ALIGN_UP(X, N) (((X) + (N - 1)) & ~(N - 1))

#define ELF_NOTE_CORE "CORE"

static void *memrchr_inv(const void *s, int c, size_t n) {
	const char *ptr = s;
	while (n && ptr[n - 1] == c)
		--n;

	return (void *)&ptr[n];
}

static const char* coredump_name(void) {
	static char out[128];

	snprintf(out, sizeof(out), "kine.%d.dump", getpid());

	return out;
}

void coredump_write(const struct user_regs_struct_i386 *regs) {
	const char* last_set_byte = memrchr_inv((void*)config.base, 0, config.limit);
	size_t filesz = last_set_byte - (const char*)config.base;

	int fd = open(coredump_name(), O_CREAT|O_WRONLY, 0644);
	if (fd < 0)
		err(1, "open");

	enum {
		PHDR_NOTE,
		PHDR_LOAD,
		PHDR_END,
	};

	struct {
		Elf32_Ehdr ehdr;
		Elf32_Phdr phdrs[PHDR_END];
		struct {
			struct {
				Elf32_Nhdr hdr;
				char name[ALIGN_UP(sizeof(ELF_NOTE_CORE), 4)];
				struct elf_prstatus_i386 desc;
			} prstatus;
		} notes __attribute__((aligned(4)));
	} coredump = {
		.ehdr = {
			.e_ident = {
				[EI_MAG0] = ELFMAG0,
				[EI_MAG1] = ELFMAG1,
				[EI_MAG2] = ELFMAG2,
				[EI_MAG3] = ELFMAG3,
				[EI_CLASS] = ELFCLASS32,
				[EI_DATA] = ELFDATA2LSB,
				[EI_VERSION] = EV_CURRENT,
				[EI_OSABI] = ELFOSABI_SYSV,
			},
			.e_type = ET_CORE,
			.e_machine = EM_386,
			.e_version = EV_CURRENT,
			.e_phoff = offsetof(typeof(coredump), phdrs),
			.e_ehsize = sizeof(coredump.ehdr),
			.e_phentsize = sizeof(coredump.phdrs[0]),
			.e_phnum = ARRSZE(coredump.phdrs),
		},
		.phdrs = {
			[PHDR_NOTE] = {
				.p_type = PT_NOTE,
				.p_offset = offsetof(typeof(coredump), notes),
				.p_filesz = sizeof(coredump.notes),
				.p_align = 4,
			},
			[PHDR_LOAD] = {
				.p_type = PT_LOAD,
				.p_offset = ALIGN_UP(sizeof(coredump), PAGE_SIZE),
				.p_filesz = filesz,
				.p_memsz = config.limit,
				.p_flags = PF_R|PF_W|PF_X,
				.p_align = PAGE_SIZE,
			},
		},
		.notes = {
			.prstatus = {
				.hdr = {
					.n_namesz = sizeof(coredump.notes.prstatus.name),
					.n_descsz = ALIGN_UP(sizeof(coredump.notes.prstatus.desc), 4),
					.n_type = NT_PRSTATUS,
				},
				.name = ELF_NOTE_CORE,
			},
		},
	};

	memcpy(&coredump.notes.prstatus.desc.pr_reg, regs, sizeof(*regs));

	if (write(fd, &coredump, sizeof(coredump)) != sizeof(coredump))
		err(1, "write");

	if (lseek(fd, coredump.phdrs[PHDR_LOAD].p_offset, SEEK_SET) < 0)
		err(1, "lseek");

	if (write(fd, (void*)config.base, filesz) < 0)
		err(1, "write");

	close(fd);
}
