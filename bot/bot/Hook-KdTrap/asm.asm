bits 64
section	.text

;imports
extern CalledHookTimes
extern CheckCallCtx
extern ExceptionHandler
extern FindExceptionRecord
extern KeBugCheck
extern OldHalQueryCounter

;exports
global HookPosition
global CalloutReturn
global GetR12
global SetR12
global GetR13
global SetR13

;HalpTscQueryCounterOrdered:
;
;	rdtscp
;	shl	  rdx, 20h
;	or	   rax, rdx
;	ret
;HalpTscQueryCounterOrdered

;r13 = exception context
HookPosition:

	push rcx
	push rdx
	sub rsp,0xE8  

	lea rax, CalledHookTimes
	lock inc qword [rax]
	   
	call CheckCallCtx
	cmp rax,1
	jne filt
	
	;to do clear KiFreezeFlag
	;fix: not neccessary to clear since no other function use it

	;is an exception
	call FindExceptionRecord
	cmp rax,0
	je dbgbreak

	mov rcx, rax
	mov rdx, r13
	call ExceptionHandler
	
	; still here so it's a debug break or something

dbgbreak:
	xor rcx, rcx
	call KeBugCheck

filt:
	add rsp, 0xE8  
	pop rdx
	pop rcx
	;jmp HalpTscQueryCounterOrdered

	jmp [OldHalQueryCounter]

;HookPosition

CalloutReturn:
	;push stack segment selector
	mov eax, ss
	push rax

	;push stack pointer
	mov rax, [rcx + 0]
	push rax

	;push arithmetic/system flags   rflags
	mov rax, [rcx + 78h]	
	;xor rax, 200h ; enable interrupts
	push rax

	;push code segment selector
	mov eax, cs
	push rax

	;push instruction pointer
	mov rax, [rcx + 8]
	push rax

	;set arguments

	mov rdx, [rcx + 18h]
	mov r8,  [rcx + 20h]
	mov r9,  [rcx + 28h]
	mov rax, [rcx + 30h]

	mov r12, [rcx + 38h]
	mov r13, [rcx + 40h]
	mov r14, [rcx + 48h]
	mov r15, [rcx + 50h]
	mov rdi, [rcx + 58h]
	mov rsi, [rcx + 60h]
	mov rbx, [rcx + 68h]
	mov rbp, [rcx + 70h]

	mov rcx, [rcx + 10h]

	;clear trace
	xor rax, rax

	;goto code
	iretq
;CalloutReturn

GetR12:
	mov rax,r12
	ret
;GetR12

SetR12:
	mov r12,rcx
	ret
;SetR12

GetR13:
	mov rax,r13
	ret
;GetR13

SetR13:
	mov r13,rcx
	ret
;SetR13
