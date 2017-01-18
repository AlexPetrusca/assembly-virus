%include "io.inc"

section .text
global CMAIN
CMAIN:
    mov eax, l2-l1
    mov eax, l3-l2
    mov eax, l4-l3
    
l1:
    mov  eax, [ebp + 22]    ;3
l2:
    lea  eax, [ebp + 0x22]  ;3
    push eax                ;1    
l3:
    lea   eax, [0xAB]
l4:

    ret
    