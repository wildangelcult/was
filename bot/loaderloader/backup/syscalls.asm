	global	sys_NtProtectVirtualMemory
	global	sys_NtCreateFile
	global	sys_NtReadFile
	global	sys_uni
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

sys_uni:
	mov r10, rcx
	mov eax, r13d
	syscall
	ret
