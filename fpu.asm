%include "io.inc"

section .data
    x: db 100

section .text
global CMAIN
CMAIN:
    mov eax, l2-l1
    mov eax, l3-l2
    mov eax, l4-l3
        
    mov  eax, 0x23    
    
l1:    
    movd xmm0, eax
l2:
    movq  xmm4, xmm0
l3:
    movd  ebx, xmm4
l4:

    ret
    