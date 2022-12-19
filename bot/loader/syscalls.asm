	global	sys_NtProtectVirtualMemory
	global	sys_NtCreateFile
	global	sys_NtReadFile
	section	.text

sys_NtProtectVirtualMemory:
	mov r10, rcx
	mov eax, 50h
	syscall
	ret

sys_NtCreateFile:
	mov r10, rcx
	mov eax, 55h
	syscall
	ret

sys_NtReadFile:
	mov r10, rcx
	mov eax, 6h
	syscall
	ret
