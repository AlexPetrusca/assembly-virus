%include "io.inc"
%include ".\common.inc"



extern _GetSystemTime@4

section .data
systime:   istruc SYSTEMTIME
    
iend

section .text
global CMAIN
CMAIN:
    mov ebp, esp; for correct debugging

    lea     eax, [systime]
    push    eax
    call    _GetSystemTime@4
    
    ;lea eax, 
    xor     ebx, ebx
    mov     bx, [systime + SYSTEMTIME.wYear]
    PRINTD  "Year", bx
    mov     bx, [systime + SYSTEMTIME.wMonth]
    PRINTD  "Month", bx
    mov     bx, [systime + SYSTEMTIME.wDayOfWeek]
    PRINTD  "DayOfWeek", bx
    mov     bx, [systime + SYSTEMTIME.wDay]
    PRINTD  "Day", bx
    mov     bx, [systime + SYSTEMTIME.wHour]
    PRINTD  "Hour", bx
    mov     bx, [systime + SYSTEMTIME.wMinute]
    PRINTD  "Minute", bx
    mov     bx, [systime + SYSTEMTIME.wSecond]
    PRINTD  "Second", bx
    mov     bx, [systime + SYSTEMTIME.wMilliseconds]    
    PRINTD  "Milliseconds", bx

    ret