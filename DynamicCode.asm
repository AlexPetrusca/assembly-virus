%include "io.inc"

extern _GetStdHandle@4
extern _WriteFile@20
extern _GetLastError@0
extern _VirtualAlloc@16
extern _VirtualProtect@16

MEM_RESERVE         equ 0x00002000
MEM_COMMIT          equ 0x00001000

PAGE_READWRITE      equ 0x04
PAGE_EXECUTE        equ 0x10


struc DATA
   .flProtect:    resb 4
   .functionAddr: resb 4
   .var1:         resb 4
   .var2:         resb 4
   .size:
endstruc

section .text
global CMAIN
CMAIN:
    mov     ebp, esp                        ; for correct debugging
    
    push    ebp                             ; save old ebp
    sub     esp, DATA.size                  ; allocate local variables
    mov     ebp, esp                        ; set ebp for variable indexing
    
    ;LPVOID WINAPI VirtualAlloc(
    ;    _In_opt_ LPVOID lpAddress,
    ;    _In_     SIZE_T dwSize,
    ;    _In_     DWORD  flAllocationType,
    ;    _In_     DWORD  flProtect);
    mov     eax, dword PAGE_READWRITE
    mov     [ebp + DATA.flProtect], eax
    push    eax                             ; flProtect
    push    dword MEM_COMMIT                ; flAllocationType
    push    dword 4096                      ; dwSize
    push    dword 0                         ; lpAddress
    call    _VirtualAlloc@16
    mov     [ebp + DATA.functionAddr], eax  ; save pointer
    
    ; copy the code
    mov     esi, function                   ; source
    mov     edi, [ebp + DATA.functionAddr]  ; destination
    mov     ecx, functionSize               ; size
    rep     movsb                           ; copy the bytes
    
    ;BOOL WINAPI VirtualProtect(
    ;    _In_  LPVOID lpAddress,
    ;    _In_  SIZE_T dwSize,
    ;    _In_  DWORD  flNewProtect,
    ;    _Out_ PDWORD lpflOldProtect
    push    ebp + DATA.flProtect            ; lpflOldProtect
    push    dword PAGE_EXECUTE              ; flNewProtect
    push    4096                            ; dwSize
    mov     eax, [ebp + DATA.functionAddr]
    push    eax                             ; lpAddress
    call    _VirtualProtect@16
                        
    mov     [ebp + DATA.var1], dword 0x99999999
    mov     [ebp + DATA.var2], dword 0x55555555
    call    [ebp + DATA.functionAddr]       ; call the functon!
    
    add     esp, DATA.size                  ; de-allocate local variables
    pop     ebp                             ; restore stack
        
    ret
    
function:
    mov     eax, [ebp + DATA.var1]
    mov     ebx, [ebp + DATA.var2]
    add     eax, ebx
    ret
endf:

functionSize equ (endf - function)
