%include "io.inc"
extern  _ExitProcess@4

global CMAIN
section .data

FileName:   db "AcroRd32.exe", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0

section .text
CMAIN:
    mov ebp, esp; for correct debugging
    xor     eax, eax
loop_findTermination:
    mov     bl, byte [FileName + eax]
    cmp     bl, 0
    je      compareEXE
    
    inc     eax
    jmp     loop_findTermination
    
       
compareEXE:
    mov     ebx, dword ".exe"
    mov     ecx, dword [FileName + eax - 4]    
    cmp     ebx, ecx   
    je      isEXE
    jne     notEXE
    
isEXE:
    PRINT_STRING "yay"
    jmp     exit

notEXE:    
    PRINT_STRING "nay"
    
exit:    
    retn