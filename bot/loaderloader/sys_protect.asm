	bits 64
	global	sys_NtProtectVirtualMemory
	global	dummyFun
	section	.text
	extern jmp_inst


sys_NtProtectVirtualMemory:
	call next
next:
	pop r11
	mov rax, jmp_inst
	movzx rax, byte [rax]
	add r11, rax
	mov r10, rcx
	mov eax, 50h
	jmp r11

dummyFun:
	xor rax, rax
	mov eax, ecx
	add eax, edx
	test eax, 0xc390050f
	jz label1
	jmp label2
label1:
	xor rax, rax
label2:
	ret
