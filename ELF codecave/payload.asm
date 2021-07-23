; writes "POC" to stdout
; compiled with "nasm -f elf payload.asm -o payload.o;ld -m elf_i386 payload.o -o payload"


section .text 
	global _start

_start:

	pushad
	
	; sys_write
	mov	edx, 	5	; arg3 = len of string

	push 	0x000a
	push 	'POC'
	mov 	ecx, 	esp	; arg2 = ptr to str

	mov 	ebx, 	1	; arg1 = 1 = stdout 
	mov 	eax, 	4	; sys_write syscall number
	int 	0x80

	popad

	push	0xAAAAAAAA	; placeholder for oep
	ret
