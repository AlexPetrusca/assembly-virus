%include "io.inc"

section .text
global CMAIN
CMAIN:
    mov eax, l2-l1
    mov eax, l3-l2
    mov eax, l4-l3
    
l1:
    cmp  eax, 0        ;3
l2:
    test eax, eax      ;2
l3:
l4:

    ret
    