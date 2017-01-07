global _main

GetStdHandle equ (6B81DA70h + 8F60000h)
WriteFile    equ (6B829D30h + 8F60000h)
ExitProcess  equ (6B82ADB0h + 8F60000h)
    
section .text
_main:
    mov ebp, esp; for correct debugging   
    mov ecx, (message_end - start)

start:
    push    ebx
    push    0                       ; local var written byte count
    mov     ebx, esp
    
    ; hStdOut = GetstdHandle(STD_OUTPUT_HANDLE)
    push    -11
    ;call    _GetStdHandle@4
    mov     ecx, GetStdHandle
    call    ecx

    ; WriteFile( hstdOut, message, length(message), &bytes, 0);
    push    0                       ; unused parameter
    push    ebx                     ; &bytes
    push    message_end - message   ; length
    call foo
foo:
    pop     ebx
    add     ebx, message - foo
    push    ebx                     ; message address
    push    eax                     ; handle to stdout
    mov     ecx, WriteFile
    call    ecx 
    
    pop     ebx                     ; destroy written
    pop     ebx                     ; restore ebx    
        
    jmp     message_end    
    message:         db 'Im a virus, motherfucker!', 10, 'GET HACKED!!!', 10
    message_end:      
exit:
    ; ExitProcess(0)
    push    0
    mov     ecx, ExitProcess
    call    ecx
    
    ; never here
    hlt
