	bits 64
	global	sys_uni
	section	.text

sys_uni:
	mov r10, rcx
	mov eax, r13d
	syscall
	ret
