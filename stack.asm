%include "io.inc"

section .data
startData:
   _var1: db 0
   _var2: dw 0
   _crap: times 512 db 0
   _var3: dd 0
endData:

dataSize equ (endData - startData)
var1 equ (_var1 - startData)
var2 equ (_var2 - startData)
var3 equ (_var3 - startData)


section .text
global CMAIN
CMAIN:
    mov ebp, esp; for correct debugging
    
    
    push    ebp                     ; save old ebp
    sub     esp, dataSize           ; allocate local variables
    mov     ebp, esp                ; set ebp for variable indexing
    ;sub     ebp, startData          ; correct for offset of startData
    
                                    ; set variables
    mov     [ebp + var1], byte 0xCC
    mov     [ebp + var3], dword 0xAAAAAAAA
    mov     [ebp + var2], word 0xBBBB
    
                                    ; read variables
    xor     eax, eax    
    mov     al, byte [ebp + var1]
    xor     eax, eax    
    mov     ax, word [ebp + var2]
    xor     eax, eax    
    mov     eax, dword [ebp + var3]
    
    add     esp, dataSize           ; de-allocate local variables
    pop     ebp                     ; restore stack
    
    
    ret