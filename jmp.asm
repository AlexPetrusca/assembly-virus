%include "io.inc"

section .data
    x: db 100

section .text
global CMAIN
CMAIN:

  mov eax, 0xBBC10300   ; 0000: B8 00 03 C1 BB
  mov ecx, 0x05000000   ; 0005: B9 00 00 00 05
  add eax, ecx          ; 000A: 03 C1
  jmp $-10              ; 000C: EB F4
  add eax, ebx          ; 000E: 03 C3
  ret                   ; 0010: C3
  
      
ret
    