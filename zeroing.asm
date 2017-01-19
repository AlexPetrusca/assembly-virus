%include "io.inc"

section .text
global CMAIN
CMAIN:
    mov eax, l2-l1
    mov eax, l3-l2
    mov eax, l4-l3

l1:
    and [ebp + 13], dword 0
l2:
    xor eax, eax
    mov [ebp + 13], eax
l3:
    mov [ebp + 13], dword 0
l4:

    ret