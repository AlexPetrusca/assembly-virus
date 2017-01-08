%include "io.inc"

%define DEBUG           1

%macro PRINTH 2
    %if DEBUG
        pushad
        PRINT_STRING %1
        PRINT_STRING ' = '
        PRINT_HEX 4, %2
        NEWLINE
        popad
    %endif
%endmacro

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

section .data
filemask:               db "*.*", 0
path: times 260         db 0
dir:  times 260         db 0
FIND_DATA: times 592    db 0
counter:                dd 100000
handle:                 dd 0
startingPath:           db "C:\Program Files (x86)\Adobe\Acrobat Reader DC"

section .text
CMAIN:
    mov     ebp, esp; for correct debugging
   
    lea     esi, [startingPath]     ; initialize path to startingPath
    lea     edi, [path]
    mov     ecx, 65
    rep     movsd 
    
    sub     esp, 260        ; create cavity for path
    lea     esi, [path]     ; copy path onto stack
    lea     edi, [esp]
    mov     ecx, 65
    rep     movsd
    mov     eax, [handle]
    push    eax
    
    ;PRINT_STRING [ebp - 260]
    ;NEWLINE
    ;PRINTH  "handle", handle
    ;NEWLINE
    ;PRINTH  "handle", [ebp - 264]
    ;NEWLINE
    
    call    crawlDirectory
    
    ;NEWLINE
    ;NEWLINE
    ;PRINT_STRING "exit"
    ;NEWLINE
    push    0
    call    _ExitProcess@4
    
    xor     eax, eax
    ret
    
    
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
 
    
; crawlDirectory(int handle, char* relativePath)
crawlDirectory:     
    push    ebp         ; prolog
    mov     ebp, esp    ; makes a fixed base pointer to refrence stack variables through 
    pushad

    ;PRINT_STRING [ebp + 12]
    ;NEWLINE
    ;NEWLINE
    ;PRINT_HEX 4, [handle]
    ;NEWLINE
    ;PRINT_HEX 4, [ebp + 8]

    push    path
    call    _SetCurrentDirectoryA@4

    cmp     eax, 0
    jne     success
      
;    call    _GetLastError@0
;    PRINTH  "_____EAX1", eax
;    NEWLINE
;    PRINT_STRING "currentDirectory: "
;    PRINT_STRING path
;    NEWLINE
;    lea     eax, [dir]
;    push    eax
;    mov     eax, 260
;    push    eax
;    call    _GetCurrentDirectoryA@8
;    PRINT_STRING [dir]
;    NEWLINE
;    NEWLINE
success:
  
;    lea     eax, [dir]
;    push    eax
;    mov     eax, 260
;    push    eax
;    call    _GetCurrentDirectoryA@8
;  
;    %if DEBUG
;    PRINT_STRING [dir]
;    NEWLINE
;    %endif
    
    ;NEWLINE
    ;PRINT_STRING "currentDirectory1: "
    ;PRINT_STRING path
    ;NEWLINE
    
    lea     eax, [FIND_DATA]
    push    eax
    lea     eax, [filemask]
    push    eax
    call    _FindFirstFileA@8
    mov     [handle], eax
    
    jmp     processFile
     
findNextFile:
    lea     eax, [FIND_DATA]
    push    eax
    mov     eax, [handle]
    push    eax
    call    _FindNextFileA@8
    
processFile:
    cmp     eax, 0
    je      exit                ; error?
    
    mov     bl, byte [FIND_DATA + 44]
    cmp     bl, 0x2e
    je      findNextFile     
    
    mov     bx, word [FIND_DATA + 44]
    cmp     bx, 0x2e2e
    je      findNextFile  
    
    lea     esi, [FIND_DATA + 44]    
    lea     edi, [path]
    mov     ecx, 65
    rep     movsd  
    
    loop_find0:
        mov     bl, byte [FIND_DATA + 44 + eax]
        cmp     bl, 0
        je      compareEXE   
    inc     eax
    jmp     loop_find0
    
    mov     ebx, [FIND_DATA]
    and     ebx, 0x10           ; 0x10 == directory proprety
    cmp     ebx, 0x10
    jne     printFile           ; if not a directory, print the file
                         
    ; else go into directory and recurse
    sub     esp, 260            ; create cavity for path
    lea     esi, [path]         ; copy path onto stack
    lea     edi, [esp]
    mov     ecx, 65
    rep     movsd  
    mov     eax, [handle]
    push    eax
    call    crawlDirectory
   
    lea     esi, [ebp + 12]      ; restore old value of path from stack
    lea     edi, [path]
    mov     ecx, 65
    rep     movsd    
    
    push    path
    call    _SetCurrentDirectoryA@4
    
    cmp     eax, 0
    jne     success1
      
;    call    _GetLastError@0
;    PRINTH  "_____EAX1", eax
;    NEWLINE
;    PRINT_STRING "currentDirectory: "
;    PRINT_STRING path
;    NEWLINE
;    lea     eax, [dir]
;    push    eax
;    mov     eax, 260
;    push    eax
;    call    _GetCurrentDirectoryA@8
;    PRINT_STRING [dir]
;    NEWLINE
;    NEWLINE
success1:
    ;NEWLINE
    ;NEWLINE
    ;PRINT_STRING "currentDirectory2: "
    ;PRINT_STRING path
    ;NEWLINE
    
    mov     eax, [counter]
    cmp     eax, 0
    je      exit                ; if counter is 0, exit
    jmp     findNextFile 

printFile:
    PRINT_STRING [FIND_DATA + 44]
    NEWLINE
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
    jne     notEXE              ; if doesnt have .exe findNextFile
        
    ; else print and decrement counter    
    ;PRINT_STRING [FIND_DATA + 44]
    ;NEWLINE
    
    dec     dword [counter]     ; decrement counter
    mov     eax, [counter]
    cmp     eax, 0
    je      exit                ; if counter is 0, exit
    
    notEXE:    
    jmp     findNextFile        ; else if not .exe continue looping

exit:   
    ;PRINTH  "counter", counter
   
    mov     eax, [handle]     ;close current find handle
    push    eax
    call    _FindClose@4
    
    ;NEWLINE
    ;PRINTH  "--------------------handle", [handle]
    ;NEWLINE
    ;PRINTH  "--------------------oldHandle", [ebp + 8]
    
    mov     eax, [ebp + 8]    ; restore old handle from stack
    mov     [handle], eax
    
    popad
    mov     esp, ebp          ; epilog 
    pop     ebp               ; restores the stack from prolog
    
    retn    264