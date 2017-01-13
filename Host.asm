global _main
extern  _GetStdHandle@4
extern  _WriteFile@20
extern  _ExitProcess@4

%macro prolog 0 
    push    ebp         ; prolog
    mov     ebp, esp    ; makes a fixed base pointer to refrence stack variables through
%endmacro

%macro epilog 0 
    mov     esp, ebp    ; epilog 
    pop     ebp         ; restores the stack from prolog
%endmacro
    
section .data
    message:         db 'Hello, World', 0, 10
    message_end:
    buffer:          times 32 db 0    

section .text
_main:   

    ; void print(char* str, int len)
    push    (message_end - message)
    push    message
    call    print
    
    ;push    (message_end - message)
    ;push    message
    ;call    print
    
    ; string itoa(int parseNum)
    push     2456989
    call     itoa
    
    push     32
    push     buffer
    call     print
    
    ; ExitProcess(0)
    push    0
    call    _ExitProcess@4
    
    ; never here
    hlt
    
; char* itoa(int parseNum)
itoa:
    push    ebp         ; prolog
    mov     ebp, esp    ; makes a fixed base pointer to refrence stack variables through
    
    push edi
    push ebx
    push ecx
    push edx
    
    ; int numDigits(int num)
    mov ebx, [ebp + 8]
    push ebx
    call numDigits
                        ; edx = must be set to 0 (after divide carries the remainder/last number)  
    mov edi, eax        ; edi = the length of the array (will be used as a decremented index)           
    dec edi             
    mov eax, [ebp + 8]  ; eax = original number that will be divided in loop
    mov ecx, 10         ; ecx = number to divide by (base 10)
    loopstart1:
        mov edx, 0
        div ecx
        add edx, 48 
        mov [buffer + edi], dl
        dec edi
        cmp eax, 0
        jnz loopstart1
        
    pop edx
    pop ecx
    pop ebx
    pop edi
    
    
    mov     esp, ebp    ; epilog 
    pop     ebp         ; restores the stack from prolog
    
    ret
    
; int numDigits(int num)
numDigits:
    push    ebp         ; prolog
    mov     ebp, esp    ; makes a fixed base pointer to refrence stack variables through    ; restores the stack from prolog
    
    
    push ebx
    push ecx
    push edx
    
    mov eax, [ebp + 8]  ; original number
    mov ecx, 10         ; number to divide by (base 10)
    mov ebx, 0          ; size counter
    loopstart2:
        inc ebx
        mov edx, 0
        div ecx
        cmp eax, 0
        jnz loopstart2
    mov eax, ebx
        
    pop edx
    pop ecx
    pop ebx
            
        
    mov     esp, ebp    ; epilog 
    pop     ebp         ; restores the stack from prolog
    
    ret 4
    

; void print(char* str, int len)
print:          
    prolog
    
    push    ebx         ; save ebx
    push    0           ; local var written byte count
    mov     ebx, esp
    
    ; hStdOut = GetstdHandle(STD_OUTPUT_HANDLE)
    push    -11
    call    _GetStdHandle@4

    ; WriteFile( hstdOut, message, length(message), &bytes, 0);
    push    0               ; unused parameter
    push    ebx             ; address of written byte count
    mov     ebx, [ebp + 12] ; length
    push    ebx
    mov     ebx, [ebp + 8]  ; message address
    push    ebx
    push    eax             ; handle to stdout
    call    _WriteFile@20
    
    pop ebx         ; destroy written
    pop ebx         ; restore ebx
    
    epilog
    
    ret 8
