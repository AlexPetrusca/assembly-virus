%include "io.inc"

section .text
global CMAIN
CMAIN:
    mov ebp, esp; for correct debugging
    
start:
    call    foo         ; read urrent EIP
foo:pop     eax
    sub     eax, 5      ; correct so that eax points to 'call foo'
    
    add     eax, (dest - start) ; add the relative jump length
    jmp     eax         ; jump

dest:        
    xor eax, eax
    
    ret
    
    
    