%include "io.inc"

struc DATA
   .var1:         resb 4
   .someFunction: resb 100
   .var2:         resb 4
   .size:
endstruc

section .text
global CMAIN
CMAIN:
    mov     ebp, esp                            ; for correct debugging
    
    push    ebp                             ; save old ebp
    sub     esp, DATA.size                  ; allocate local variables
    mov     ebp, esp                        ; set ebp for variable indexing
    
    mov     edx, ebp                        ; compute address of function in the stack
    add     edx, DATA.someFunction
        
                                            ; copy the function into the stack!
    mov     esi, function                   ; source
    mov     edi, edx                        ; destination
    mov     ecx, functionSize               ; size
    rep     movsb                           ; copy the bytes
    
                        
    mov     [ebp + DATA.var1], dword 0x99999999
    mov     [ebp + DATA.var2], dword 0x66666666
    call    edx                             ; call the functon!
    
    add     esp, DATA.size                  ; de-allocate local variables
    pop     ebp                             ; restore stack
        
    ret
    
function:
    mov     eax, [ebp + DATA.var1]
    mov     ebx, [ebp + DATA.var2]
    add     eax, ebx
    call    foo
foo:pop     ebx
    ret
endf:

functionSize equ (endf - function)
