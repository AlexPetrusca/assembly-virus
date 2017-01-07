global _main

extern _GetStdHandle@4
extern _WriteFile@20
    
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
    call    _GetStdHandle@4

    ; WriteFile( hstdOut, message, length(message), &bytes, 0);
    push    0                       ; unused parameter
    push    0                     ; &bytes
    push    message_end - message   ; length
    call foo
foo:
    pop     ebx
    add     ebx, message - foo
    push    ebx                     ; message address
    push    eax                     ; handle to stdout
    call    _WriteFile@20 
    
    pop     ebx                     ; destroy written
    pop     ebx                     ; restore ebx    
        
    jmp     exit    
    
    message:         db 'Im a virus, motherfucker!', 10, 'GET HACKED!!!', 10
    message_end: 
         
exit:
    ret
