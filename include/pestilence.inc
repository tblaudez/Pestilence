; SYSCALL
%assign SYSCALL_READ		0
%assign SYSCALL_WRITE		1
%assign SYSCALL_OPEN		2
%assign SYSCALL_CLOSE		3
%assign SYSCALL_FSTAT		5
%assign SYSCALL_MMAP		9
%assign SYSCALL_MUNMAP		11
%assign SYSCALL_MREMAP		25
%assign SYSCALL_FORK		57
%assign SYSCALL_EXIT		60
%assign SYSCALL_FTRUNCATE	77
%assign SYSCALL_GETDENTS	78
%assign SYSCALL_CHMOD		90
%assign SYSCALL_SETSID		112

; Constant values
%define PAYLOAD_SIZE		(_end - _start)
%define VALUE(x)			[(rbp - s_pestilence_size) + x]
%assign	DIRENT_ARR_SIZE		1024
%assign	PATH_MAX			4096
%define SIGNATURE_SIZE		(processDirectory - signature)

; File access options
%assign	O_RDONLY			0o0000000
%assign	O_RDWR				0o0000002
%assign	O_DIRECTORY			0o0200000

; getdents options
%assign	DT_REG				8
%assign	DT_DIR				4

; mmap options
%assign	PROT_READ			0x1
%assign	PROT_WRITE			0x2
%assign	MAP_SHARED 			0x01
%assign	MMAP_ERROR          -4095

; ELF header data for comparisons
%assign	ELF_SYSV			0x00010102464c457f
%assign	ELF_GNU				0x03010102464c457f
%assign	ELF64_AND_DYN		0x00000001003e0003
%assign	ELF64_AND_EXEC		0x00000001003e0002

; ELF segment data
%assign	PT_NOTE				0x4
%assign	PT_LOAD				0x1
%assign	PAGE_SIZE			0x1000

; Directory entry structure
struc	dirent
	.d_ino:			resq	1	; 64-bit inode number
	.d_off:			resq	1	; 64-bit offset to next structure
	.d_reclen		resw	1	; Size of this dirent
	.d_name			resb	1	; Filename (null-terminated)
endstruc

; File stat structure
struc	stat
	.st_dev			resq	1	; ID of device containing file
	.__pad1			resw	1	; Padding
	.st_ino			resq	1	; Inode number
	.st_mode		resd	1	; File type and mode
	.st_nlink		resq	1	; Number of hard links
	.st_uid			resd	1	; User ID of owner
	.st_gid			resd	1	; Group ID of owner
	.st_rdev		resq	1	; Device ID (if special file)
	.__pad2			resw	1	; Padding
	.st_size		resq	1	; Total size, in bytes
	.st_blksize		resq	1	; Block size for filesystem I/O
	.st_blocks		resq	1	; Number of 512B blocks allocated
	.st_atim		resq	2	; Time of last access
	.st_mtim		resq	2	; Time of last modification
	.st_ctim		resq	2	; Time of last status change
	.__unused		resq	3	; Unused
endstruc

; ELF Entry Header
struc	elf64_ehdr
	.e_ident		resb	16	; Magic number and other info
	.e_type			resw	1	; Object file type
	.e_machine		resw	1	; Architecture
	.e_version		resd	1	; Object file version
	.e_entry		resq	1	; Entry point virtual address
	.e_phoff		resq	1	; Program header table file offset
	.e_shoff		resq	1	; Section header table file offset
	.e_flags		resd	1	; Processor-specific flags
	.e_ehsize		resw	1	; ELF header size in bytes
	.e_phentsize	resw	1	; Program header table entry size
	.e_phnum		resw	1	; Program header table entry count
	.e_shentsize	resw	1	; Section header table entry size
	.e_shnum		resw	1	; Section header table entry count
	.e_shstrndx		resw	1	; Section header string table index
endstruc

; ELF Program Header
struc	elf64_phdr
	.p_type			resd	1	; Segment type
	.p_flags		resd	1	; Segment flags
	.p_offset		resq	1	; Segment file offset
	.p_vaddr		resq	1	; Segment virtual address
	.p_paddr		resq	1	; Segment physical address
	.p_filesz		resq	1	; Segment size in file
	.p_memsz		resq	1	; Segment size in memory
	.p_align		resq	1	; Segment alignment
endstruc

; Self data structure
struc	s_pestilence
	.dirents		resb	DIRENT_ARR_SIZE	; Array of dirents
	.dir_fd			resq	1				; Directory fd
	.file_path		resb	PATH_MAX		; File path buffer
	.file_fd		resq	1				; Open file fd
	.stat			resb	stat_size		; Buffer for stat struct
	.file_size		resq	1				; Size of open file
	.file_data		resq	1				; Pointer to mmapped file data
endstruc