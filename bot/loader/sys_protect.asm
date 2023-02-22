	global	sys_NtProtectVirtualMemory
	section	.text

sys_NtProtectVirtualMemory:
	mov r10, rcx
	mov eax, 50h
	syscall
	ret
