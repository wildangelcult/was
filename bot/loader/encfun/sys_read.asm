	bits 64
	global	sys_NtReadFile
	section	.text

sys_NtReadFile:
	mov r10, rcx
	mov eax, 6h
	syscall
	ret
