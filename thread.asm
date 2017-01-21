%include "io.inc"

extern  _CreateThread@24
extern  _WaitForSingleObject@8

COUNT                equ 20

section .data
    threadId1        dd 1
    threadId2        dd 1
    threadHandle1    dd 1
    threadHandle2    dd 1
    str1             db "Hello", 10, 0
    str2             db "Aloha", 10, 0

section .text
global CMAIN
CMAIN:

    push    threadId1       ; the threadId will be placed there
    push    0               ; run immediately
    push    0               ; no parameter
    push    threadFun1      ; pointer to function
    push    0               ; default stack size
    push    0               ; default attributes
    call    _CreateThread@24
    mov     [threadHandle1], eax
      
    push    threadId2       ; the threadId will be placed there
    push    0               ; run immediately
    push    0               ; no parameter
    push    threadFun2      ; pointer to function
    push    0               ; default stack size
    push    0               ; default attributes
    call    _CreateThread@24
    mov     [threadHandle2], eax
    
    push    0xffffffff      ; wait indefinitely
    push    dword [threadHandle1]
    call    _WaitForSingleObject@8

    push    0xffffffff      ; wait indefinitely
    push    dword [threadHandle2]
    call    _WaitForSingleObject@8

    retm
    
threadFun1:    
    mov     ecx, COUNT
again1:
    PRINT_STRING str1
    dec     ecx
    jnz     again1    
    mov     eax, 0
    retn
    
threadFun2:
    mov     ecx, COUNT
again2:
    PRINT_STRING str2
    dec     ecx
    jnz     again2  
    mov     eax, 0
    retn    