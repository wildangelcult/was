; Calling Syscall 7fh (NtGetTickCount) via x64 bit Assembly
; by Timb3r 2019
;
; nasm.exe -f win64 main.asm -o main.obj                                                                                
; gcc.exe -o syscall.exe main.obj                          
;
global main                                                                                                                
extern printf                                                                                                              

section .data                                                                                                              
        szMsg: db "NtGetTickCount: %lld",0                                                                                

section .text                                                                                                              
    main:                                                                                                                  
        push    rbp                                                                                                
        mov     rbp,rsp                                                                                                    
        sub     rsp,20h                                                                                            
                                                                                                                           
        mov     rcx, 0                                                                                                
        mov     r10, rcx                                                                                              
        mov     eax, 7fh ; NtGetTickCount                                                                              
        syscall                                                                                                    

        mov     rcx, szMsg                                                                                                
        mov     rdx, rdi                                                                                          

        call    printf                                                                                                    

        add     rsp,20h                                                                                                    
        mov     rsp,rbp                                                                                                    
        pop     rbp                                                                                                        
        ret
