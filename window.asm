%include "io.inc"
%include "./common.inc"

extern _EnumWindows@8
extern _IsWindowVisible@4
extern _InternalGetWindowText@12
extern _MoveWindow@24

section .data
    count            dd 1
    text  times 1024 db 0

section .text
global CMAIN
CMAIN:

    
    push    13                   ; the parameter
    push    EnumWindowsProc     ; the enumeration function
    call    _EnumWindows@8
   ; PRINTH  "eax", eax

    ret
    
;HWND   hwnd,
;LPARAM lParam    
EnumWindowsProc:
    push    dword [esp + 4]   ; handle
    call    _IsWindowVisible@4
    cmp     eax, 0
    je      return
    
;    push    1024
;    push    text
;    push    dword [esp + 4]   ; handle
;    call    _InternalGetWindowText@12
;    PRINTS  "text", text

    push    1
    push    0
    push    0
    push    0
    push    0    
    push    dword [esp + 4] 
    call    _MoveWindow@24

    mov     eax, dword [esp + 4]   ; handle
    PRINTH  "window", eax

return:
    mov     eax, 1              ; return true
    ret     8   