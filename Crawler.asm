%include "io.inc"
%include "./common.inc"

COUNT               equ 100000
MAX_PATH_LENGTH     equ 260
DIRECTORY           equ 10h

global CMAIN
extern  _FindFirstFileA@8
extern  _FindNextFileA@8
extern  _FindClose@4
extern  _lstrcpy@8
extern  _lstrcat@8
extern  _ExitProcess@4

struc DATA
    .fileMask:               resb 5 ; 0x5C2A2E2A "\*.*"
    .backslash:              resb 2 ; "\", 0   ; 0x5C ; "\"
    .findData:              resb 592
    .findHandle:             resd 1
    .counter:                resd 1 ; COUNT
    .currentPath:            resb 260
    .searchPath:             resb 260    
    .size:
endstruc

section .data
    startingPath: db "C:\Program Files (x86)", 0  ; must be fixed when ported

section .text
CMAIN:
    
    ; create stack frame for the local variables
    push    ebp                                 ; save old ebp
    sub     esp, DATA.size                      ; allocate local variables
    mov     ebp, esp                            ; set ebp for variable indexing

    ; initialize local variables    
    mov     [ebp + DATA.fileMask], dword 0x2A2E2A5C ; "\*.*"
    mov     [ebp + DATA.fileMask + 4], byte 0 ; 0 terminator
    mov     [ebp + DATA.backslash], word 0x005C ; "\"    
    mov     [ebp + DATA.counter], dword COUNT

    ; push initial path onto the stack
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
    lea     edx, [ebp + DATA.currentPath]
    push    edx
    call    _lstrcpy@8
    add     esp, MAX_PATH_LENGTH
    ;PRINTS  "currentPath", [ebp + DATA.currentPath]
    
    lea     edx, [ebp + DATA.currentPath]   ; copy currentPath into searchPath
    push    edx
    lea     edx, [ebp + DATA.searchPath] 
    push    edx
    call    _lstrcpy@8
    ;PRINTS  "searchPath", [ebp + DATA.searchPath]
    
    lea     edx, [ebp + DATA.fileMask]            ; append the file mask
    push    edx
    lea     edx, [ebp + DATA.searchPath]
    push    edx
    call    _lstrcat@8
    ;PRINTS  "searchPath", [ebp + DATA.searchPath]
    
    lea     edx, [ebp + DATA.findData]           ; find the first file
    push    edx
    lea     edx, [ebp + DATA.searchPath]
    push    edx
    call    _FindFirstFileA@8
    cmp     eax, -1             ; invalid handle? 
    je      next_dir            ; no need to close the search, just move on
    mov     [ebp + DATA.findHandle], eax
    jmp     process_file        ; else process the file
    
next_file:
    lea     edx, [ebp + DATA.findData]
    push    edx
    mov     eax, [ebp + DATA.findHandle]
    push    eax
    call    _FindNextFileA@8
    cmp     eax, 0
    je      close_search
    
process_file:
    ; skip '.' and '..' directories
    cmp     word [ebp + DATA.findData + FIND_DATA.cFileName], word 0x002e
    je      next_file
    cmp     word [ebp + DATA.findData + FIND_DATA.cFileName], word 0x2e2e
    je      next_file
    
    lea     edx, [ebp + DATA.currentPath]         ; get file absolute path
    push    edx
    lea     edx, [ebp + DATA.searchPath]
    push    edx
    call    _lstrcpy@8
    lea     edx, [ebp + DATA.backslash]
    push    edx
    lea     edx, [ebp + DATA.searchPath]
    push    edx
    call    _lstrcat@8
    lea     edx, [ebp + DATA.findData + FIND_DATA.cFileName]
    push    edx
    lea     edx, [ebp + DATA.searchPath]
    push    edx
    call    _lstrcat@8
    
    mov     eax, [ebp + DATA.findData + FIND_DATA.dwFileAttributes]
    and     eax, DIRECTORY 
    cmp     eax, DIRECTORY      ; directory?
    je      dir                 ; then its a dir
    
    ; else its a file and check if exe
    xor     eax, eax
loop_findTermination:
    mov     bl, byte [ebp + DATA.findData + FIND_DATA.cFileName + eax]
    cmp     bl, 0
    je      compareEXE    
    inc     eax
    jmp     loop_findTermination    
    
compareEXE:
    mov     ebx, dword ".exe"
    mov     ecx, dword [ebp + DATA.findData + FIND_DATA.cFileName + eax - 4]    
    cmp     ebx, ecx   
    jne     next_file

    ;;;;; IF FILE AND EXE, THEN INFECT ;;;;;
    PRINTS  "FILE", [ebp + DATA.searchPath]
    
    dec     dword [ebp + DATA.counter]      ; decrement counter and loop again
    jz      exit
    jmp     next_file
    
dir:
    sub     esp, MAX_PATH_LENGTH
    mov     ebx, esp
    lea     edx, [ebp + DATA.searchPath]
    push    edx
    push    ebx
    call    _lstrcpy@8
    jmp     next_file
    
close_search:
    ;findData "closeSearch", [ebp + DATA.currentPath]
    mov     eax, [ebp + DATA.findHandle]
    push    eax
    call    _FindClose@4
    jmp     next_dir

exit:
    mov     eax, COUNT
    sub     eax, [ebp + DATA.counter]
    NEWLINE
    PRINTD "counter", eax
    
    add     esp, DATA.size                  ; de-allocate local variables
    pop     ebp                             ; restore stack

end:

    push    0
    call    _ExitProcess@4
    

    