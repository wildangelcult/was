	bits 64	
	global	sys_NtCreateFile
	section	.text

sys_NtCreateFile:
	mov r10, rcx
	mov eax, 55h
	syscall
	ret
