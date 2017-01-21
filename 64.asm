global main

section .text

main:
    mov     rax, l2 - l1

    xor     rax, rax
    not     rax
l1:
    xor     eax, eax
l2:
    
target:	
    ret