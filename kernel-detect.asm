global _main
    
section .data  
    dwKernelBase:           dd    0
    dwExportDirectory:      dd    0                        

section .text8
_main:
    mov ebp, esp            ; for correct debugging
  
    mov ebx, [FS : 0x30]    ; PEB
    mov ebx, [ebx + 0x0C]   ; PEB->Ldr
    mov ebx, [ebx + 0x14]   ; PEB->Ldr.InMemoryOrderModuleList.Flink (1st entry)
    mov ebx, [ebx]          ; 2nd Entry
    mov ebx, [ebx]          ; 3rd Entry
    mov ebx, [ebx + 0x10]   ; Third entry's base address (Kernel32.dll)
    mov [dwKernelBase] , ebx
    
    add ebx, [ebx+0x3C]     ; Start of PE header, skip DOS header
    mov ebx, [ebx+0x78]     ; RVA of export dir
    add ebx, [dwKernelBase]  ; VA of export dir
    mov [dwExportDirectory] , ebx
    
    retn
    
    ; never here
    hlt
