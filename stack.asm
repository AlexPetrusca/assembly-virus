%include "io.inc"

struc DATA
   .var1: resb 1
   .var2: resw 1
   .var3: resd 1
endstruc


section .data
data: istruc DATA 
endData:

dataSize equ (endData - data)

section .text
global CMAIN
CMAIN:
    mov ebp, esp; for correct debugging
    
    push    ebp                     ; save old ebp
    sub     esp, dataSize           ; allocate local variables
    mov     ebp, esp                ; set ebp for variable indexing
    
                                    ; set variables
    mov     [ebp + DATA.var1], byte 0xAA
    mov     [ebp + DATA.var3], dword 0xBBBBBBBB
    mov     [ebp + DATA.var2], word 0xCCCC
    
                                    ; read variables
    xor     eax, eax    
    mov     al, byte [ebp + DATA.var1]
    xor     eax, eax    
    mov     ax, word [ebp + DATA.var2]
    xor     eax, eax    
    mov     eax, dword [ebp + DATA.var3]
    
    add     esp, dataSize           ; de-allocate local variables
    pop     ebp                     ; restore stack
    
    
    ret