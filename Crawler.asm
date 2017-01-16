%include "io.inc"
%include "./common.inc"

COUNT               equ 100000
STACK_SIZE          equ 100
MAX_PATH_LENGTH     equ 260
DIRECTORY           equ 10h

global CMAIN
extern  _GetStdHandle@4
extern  _WriteFile@20
extern  _ExitProcess@4
extern  _FindFirstFileA@8
extern  _FindNextFileA@8
extern  _GetCurrentDirectoryA@8
extern  _SetCurrentDirectoryA@4
extern  _GetLastError@0
extern  _FindClose@4
extern  _lstrcpy@8
extern  _lstrcat@8
extern printf

section .data
fileMask:               db "\*.*", 0
backslash:              db "\", 0
FIND_DATA: times 592    db 0
findHandle:             dd 0
counter:                dd COUNT
currentPath: times 260  db 0
searchPath: times 260   db 0

startingPath:           db "C:\Program Files (x86)", 0  ; must be fixed when ported

section .text
CMAIN:
    mov     ebp, esp
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    sub     esp, MAX_PATH_LENGTH
    mov     ebx, esp
    push    startingPath
    push    ebx
    call    _lstrcpy@8
    ;PRINTS  "startPath", [ebx]
    
next_dir:
    cmp     ebp, esp            ; must be fixed when ported
    je      exit

    push    esp                 ; pop path off the stack
    push    currentPath
    call    _lstrcpy@8
    add     esp, MAX_PATH_LENGTH
    ;PRINTS  "currentPath", currentPath
    
    push    currentPath         ; copy currentPath into searchPath
    push    searchPath
    call    _lstrcpy@8
    
    push    fileMask            ; append the file mask
    push    searchPath
    call    _lstrcat@8
    ;PRINTS  "searchPath", searchPath
    ;NEWLINE
    
    push    FIND_DATA           ; find the first file
    push    searchPath
    call    _FindFirstFileA@8
    cmp     eax, -1             ; invalid handle? 
    je      close_search        ; then error and close_search
    mov     [findHandle], eax
    jmp     process_file        ; else process the file
    
next_file:
    push    FIND_DATA
    mov     eax, [findHandle]
    push    eax
    call    _FindNextFileA@8
    cmp     eax, 0
    je      close_search
    
process_file:
    ;PRINTS "fileName", [FIND_DATA + 44]
    ; skip '.' and '..' directories
    cmp     word [FIND_DATA + 44], word 0x002e
    je      next_file
    cmp     word [FIND_DATA + 44], word 0x2e2e
    je      next_file
    
    push    currentPath         ; get file absolute path
    push    searchPath
    call    _lstrcpy@8
    push    backslash
    push    searchPath
    call    _lstrcat@8
    lea     eax, [FIND_DATA + 44]
    push    eax
    push    searchPath
    call    _lstrcat@8
    
    mov     eax, [FIND_DATA + 0]
    and     eax, DIRECTORY 
    cmp     eax, DIRECTORY      ; directory?
    je      dir                 ; then its a dir
    
    ; else its a file and check if exe
    xor     eax, eax
loop_findTermination:
    mov     bl, byte [FIND_DATA + 44 + eax]
    cmp     bl, 0
    je      compareEXE
    
    inc     eax
    jmp     loop_findTermination
    
compareEXE:
    mov     ebx, dword ".exe"
    mov     ecx, dword [FIND_DATA + 44 + eax - 4]    
    cmp     ebx, ecx   
    jne     next_file

    ;;;;; IF FILE AND EXE, THEN INFECT ;;;;;
    PRINTS  "FILE", searchPath
    dec     dword [counter]
    jz      exit
    jmp     next_file
    
dir:
    sub     esp, MAX_PATH_LENGTH
    mov     ebx, esp
    push    searchPath
    push    ebx
    call    _lstrcpy@8
    jmp     next_file
    
close_search:
    mov     eax, [findHandle]
    push    eax
    call    _FindClose@4
    jmp     next_dir

exit:
    mov     eax, COUNT
    sub     eax, [counter]
    NEWLINE
    PRINTD "counter", eax
    
    push    0
    call    _ExitProcess@4
    