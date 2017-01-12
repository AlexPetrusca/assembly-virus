%define DEBUG       0

NULL            equ 0

; markers
ZM              equ 0x5A4D
EP              equ 0x4550
AD              equ 0x4144
AD_OFFSET       equ 0x38

; machine types
INTEL386        equ 0x014C

; instruction opcodes
JMP_NR          equ 0xE9
JMP_NR_BYTES    equ 5

; segment characteristics
CODE            equ 0x00000020
EXECUTABLE      equ 0x20000000
READABLE        equ 0x40000000
WRITABLE        equ 0x80000000

extern  _ExitProcess@4

%macro PRINTH 2
    %if DEBUG
        pushad
        PRINT_STRING %1
        PRINT_STRING ' = 0x'
        PRINT_HEX 4, %2
        NEWLINE
        popad
    %endif
%endmacro

%macro PRINTD 2
    %if DEBUG
        pushad
        PRINT_STRING %1
        PRINT_STRING ' = '
        PRINT_DEC 4, %2
        NEWLINE
        popad
    %endif
%endmacro

%macro PRINT_FILE 1 
    %if DEBUG
        pushad
        mov dword[counter], 1
        NEWLINE
        PRINT_STRING %1
        NEWLINE
        popad
    %endif
%endmacro

%macro PRINT_TRACE 0 
    %if DEBUG 
;        pushad
;        PRINT_DEC    4, [counter]
;        PRINT_STRING ": "
;        PRINT_HEX    4, esp
;        PRINT_STRING "  "
;        PRINT_HEX    4, eax
;        NEWLINE
;        inc dword[counter]
;        popad
    %endif
%endmacro

%macro NOPS 0
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
%endmacro

struc OVERLAPPED
    .internal:           resd 1
    .internalHigh:       resd 1
    .offset:             resd 1
    .offsetHigh:         resd 1
    .handle:             resd 1
    .size:
endstruc

struc SYSTEMTIME 
   .wYear:           resw 1
   .wMonth:          resw 1
   .wDayOfWeek:      resw 1
   .wDay:            resw 1
   .wHour:           resw 1
   .wMinute:         resw 1
   .wSecond:         resw 1
   .wMilliseconds:   resw 1
   .size:
endstruc

struc DOS
  .signature:            resw 1   ; 0x00   = 0x5a4D (ZM)
  .bytes_in_last_block:  resw 1   ; 0x02
  .blocks_in_file:       resw 1   ; 0x04
  .num_relocs:           resw 1   ; 0x06
  .header_paragraphs:    resw 1   ; 0x08
  .min_extra_paragraphs: resw 1   ; 0x0A
  .max_extra_paragraphs: resw 1   ; 0x0C
  .ss:                   resw 1   ; 0x0E
  .sp:                   resw 1   ; 0x10
  .checksum:             resw 1   ; 0x12
  .ip:                   resw 1   ; 0x14
  .cs:                   resw 1   ; 0x16
  .reloc_table_offset:   resw 1   ; 0x18
  .overlay_number:       resw 1   ; 0x1A
  .reserved1:            resw 4   ; 0x1C
  .oemid:                resw 1   ; 0x24
  .oeminfo:              resw 1   ; 0x26
  .reserved2:            resw 10  ; 0x28
  .lfanew:               resd 1   ; 0x3C
  .size:                          ; 0x40
endstruc

struc PE
    .Signature:                      resd 1  ; 0x00 = 0x50450000
    .Machine:                        resw 1  ; 0x04
    .NumberOfSections:               resw 1  ; 0x06
    .TimeDateStamp:                  resd 1  ; 0x08
    .PointerToSymbolTable:           resd 1  ; 0x0C
    .NumberOfSymbols:                resd 1  ; 0x10
    .SizeOfOptionalHeader:           resw 1  ; 0x14
    .Characteristics:                resw 1  ; 0x16
    .Magic:                          resw 1  ; 0x18 = 0x010B ?
    .MajorLinkerVersion:             resb 1  ; 0x1A
    .MinorLinkerVersion:             resb 1  ; 0x1B
    .SizeOfCode:                     resd 1  ; 0x1C      ; <--
    .SizeOfInitializedData:          resd 1  ; 0x20
    .SizeOfUninitializedData:        resd 1  ; 0x24
    .AddressOfEntryPoint:            resd 1  ; 0x28
    .BaseOfCode:                     resd 1  ; 0x2C
    .BaseOfData:                     resd 1  ; 0x30
    .ImageBase:                      resd 1  ; 0x34
    .SectionAlignment:               resd 1  ; 0x38
    .FileAlignment:                  resd 1  ; 0x3C
    .MajorOperatingSystemVersion:    resw 1  ; 0x40
    .MinorOperatingSystemVersion:    resw 1  ; 0x42
    .MajorImageVersion:              resw 1  ; 0x44
    .MinorImageVersion:              resw 1  ; 0x46
    .MajorSubsystemVersion:          resw 1  ; 0x48
    .MinorSubsystemVersion:          resw 1  ; 0x4A
    .Reserved1:                      resd 1  ; 0x4C
    .SizeOfImage:                    resd 1  ; 0x50     ; <--
    .SizeOfHeaders:                  resd 1  ; 0x54
    .CheckSum:                       resd 1  ; 0x58     ; <-- fixed
    .Subsystem:                      resw 1  ; 0x5C
    .DllCharacteristics:             resw 1  ; 0x5E
    .SizeOfStackReserve:             resd 1  ; 0x60
    .SizeOfStackCommit:              resd 1  ; 0x64
    .SizeOfHeapReserve:              resd 1  ; 0x68
    .SizeOfHeapCommit:               resd 1  ; 0x6C
    .LoaderFlags:                    resd 1  ; 0x70
    .NumberOfRvaAndSizes:            resd 1  ; 0x74
    .size:                                   ; = 0x78
endstruc

struc SECTIONH
    .Name:                  resb   8   ; 0x00
    .VirtualSize:           resd   1   ; 0x08
    .VirtualAddress:        resd   1   ; 0x0C
    .SizeOfRawData:         resd   1   ; 0x10
    .PointerToRawData:      resd   1   ; 0x14
    .PointerToRelocations:  resd   1   ; 0x18
    .PointerToLinenumbers:  resd   1   ; 0x1C
    .NumberOfRelocations:   resw   1   ; 0x20
    .NumberOfLinenumbers:   resw   1   ; 0x22
    .Characteristics:       resd   1   ; 0x24
    .size:                             ; = 0x28
endstruc

struc FIND_DATA
   .dwFileAttributes:       resd   1   ; 0x00
   .ftCreationTimeL:        resd   1   ; 0x04
   .ftCreationTimeH:        resd   1   ; 0x08
   .ftLastAccessTimeL:      resd   1   ; 0x0C
   .ftLastAccessTimeH:      resd   1   ; 0x10
   .ftLastWriteTimeL:       resd   1   ; 0x14
   .ftLastWriteTimeH:       resd   1   ; 0x18
   .nFileSizeHigh:          resd   1   ; 0x1C
   .nFileSizeLow:           resd   1   ; 0x20
   .dwReserved0:            resd   1   ; 0x24
   .dwReserved1:            resd   1   ; 0x28
   .cFileName:              resb   520 ; 0x2C
   .cAlternateFileName:     resb   28  ; 0x234
   .size:                              ; = 0x250
endstruc

AcquireSRWLockExclusiveHash equ 0x5ca43371
AcquireSRWLockSharedHash equ 0xb079a072
ActivateActCtxHash equ 0x5181bb28
AddAtomAHash equ 0xb88a890f
AddAtomWHash equ 0xb88a8925
AddConsoleAliasAHash equ 0x84843127
AddConsoleAliasWHash equ 0x8484313d
AddDllDirectoryHash equ 0x5f40950a
AddIntegrityLabelToBoundaryDescriptorHash equ 0x12c43bbc
AddLocalAlternateComputerNameAHash equ 0xad599e6b
AddLocalAlternateComputerNameWHash equ 0xad599e81
AddRefActCtxHash equ 0x8c32bb27
AddSIDToBoundaryDescriptorHash equ 0x89637d41
AddSecureMemoryCacheCallbackHash equ 0xac8d63ee
AddVectoredContinueHandlerHash equ 0xc6c6c560
AddVectoredExceptionHandlerHash equ 0x857552de
AdjustCalendarDateHash equ 0x61d1f95b
AllocConsoleHash equ 0xe5421882
AllocateUserPhysicalPagesHash equ 0x93c86545
AllocateUserPhysicalPagesNumaHash equ 0x02ff7480
ApplicationRecoveryFinishedHash equ 0x6ba8d077
ApplicationRecoveryInProgressHash equ 0x8fc26137
AreFileApisANSIHash equ 0x780dd64c
AssignProcessToJobObjectHash equ 0x9223f6a1
AttachConsoleHash equ 0x39191732
BackupReadHash equ 0x3f246e98
BackupSeekHash equ 0x3f24e37a
BackupWriteHash equ 0xa5b5e31d
BaseCheckAppcompatCacheHash equ 0x6a5b24d6
BaseCheckAppcompatCacheExHash equ 0x40255029
BaseCheckRunAppHash equ 0x7d1dbf0d
BaseCleanupAppcompatCacheSupportHash equ 0x4d242dbd
BaseDllReadWriteIniFileHash equ 0x4f7241aa
BaseDumpAppcompatCacheHash equ 0x0f2f4c44
BaseFlushAppcompatCacheHash equ 0xfbcb51d2
BaseFormatObjectAttributesHash equ 0xab35c05e
BaseFormatTimeOutHash equ 0xf1f6a5d9
BaseGenerateAppCompatDataHash equ 0x53890d67
BaseGetNamedObjectDirectoryHash equ 0x481b93ba
BaseInitAppcompatCacheSupportHash equ 0x55f5554f
BaseIsAppcompatInfrastructureDisabledHash equ 0xd3fd5e87
BaseQueryModuleDataHash equ 0x8eab6bed
BaseSetLastNTErrorHash equ 0xf928041b
BaseThreadInitThunkHash equ 0x786520b3
BaseUpdateAppcompatCacheHash equ 0x5b3f4219
BaseVerifyUnicodeStringHash equ 0x24453ea4
Basep8BitStringToDynamicUnicodeStringHash equ 0xdb308fcf
BasepAllocateActivationContextActivationBlockHash equ 0xc8c9143a
BasepAnsiStringToDynamicUnicodeStringHash equ 0x7d351c7d
BasepCheckAppCompatHash equ 0x7bcf8e5a
BasepCheckBadappHash equ 0x94ef4a05
BasepCheckWinSaferRestrictionsHash equ 0x04c63719
BasepFreeActivationContextActivationBlockHash equ 0xc531d6e9
BasepFreeAppCompatDataHash equ 0x0d39fe62
BasepMapModuleHandleHash equ 0xaccc9191
BeepHash equ 0x001f884e
BeginUpdateResourceAHash equ 0x8b376361
BeginUpdateResourceWHash equ 0x8b376377
BindIoCompletionCallbackHash equ 0xad4fd404
BuildCommDCBAHash equ 0xed5f4278
BuildCommDCBAndTimeoutsAHash equ 0x9aa1a8c1
BuildCommDCBAndTimeoutsWHash equ 0x9aa1a8d7
BuildCommDCBWHash equ 0xed5f428e
CallNamedPipeAHash equ 0xf15fcdb8
CallNamedPipeWHash equ 0xf15fcdce
CallbackMayRunLongHash equ 0xa187a4c7
CancelDeviceWakeupRequestHash equ 0xdae5dea0
CancelIoHash equ 0xfc82e560
CancelIoExHash equ 0xe75f1633
CancelSynchronousIoHash equ 0x8a7335d5
CancelThreadpoolIoHash equ 0x817140a6
CancelTimerQueueTimerHash equ 0x5df527df
CancelWaitableTimerHash equ 0xa0beabbc
ChangeTimerQueueTimerHash equ 0x2a566fe9
CheckElevationHash equ 0x31af5e55
CheckElevationEnabledHash equ 0x8af6eb2c
CheckForReadOnlyResourceHash equ 0x200c9171
CheckNameLegalDOS8Dot3AHash equ 0x3b68b721
CheckNameLegalDOS8Dot3WHash equ 0x3b68b737
CheckRemoteDebuggerPresentHash equ 0x5b92cc2c
ClearCommBreakHash equ 0x152f3da6
ClearCommErrorHash equ 0x1559b6af
CloseConsoleHandleHash equ 0xb7a42367
CloseHandleHash equ 0x59e68620
ClosePrivateNamespaceHash equ 0xec635510
CloseProfileUserMappingHash equ 0x98378912
CloseThreadpoolHash equ 0x9c12ed1e
CloseThreadpoolCleanupGroupHash equ 0x478aba79
CloseThreadpoolCleanupGroupMembersHash equ 0x59059c60
CloseThreadpoolIoHash equ 0xe30c26e4
CloseThreadpoolTimerHash equ 0xc3bbacc7
CloseThreadpoolWaitHash equ 0x50a433b3
CloseThreadpoolWorkHash equ 0x50a4694f
CmdBatNotificationHash equ 0xe7bbf926
CommConfigDialogAHash equ 0xcbf1868b
CommConfigDialogWHash equ 0xcbf186a1
CompareCalendarDatesHash equ 0x04427522
CompareFileTimeHash equ 0xe978424e
CompareStringAHash equ 0x77c06dcb
CompareStringExHash equ 0x804d4c89
CompareStringOrdinalHash equ 0x4e5df05b
CompareStringWHash equ 0x77c06de1
ConnectNamedPipeHash equ 0x98ebdadd
ConsoleMenuControlHash equ 0x429f8147
ContinueDebugEventHash equ 0x7a53482e
ConvertCalDateTimeToSystemTimeHash equ 0xa965178d
ConvertDefaultLocaleHash equ 0x2962bd28
ConvertFiberToThreadHash equ 0x2da4ae9e
ConvertNLSDayOfWeekToWin32DayOfWeekHash equ 0x64b10d0c
ConvertSystemTimeToCalDateTimeHash equ 0x546964bf
ConvertThreadToFiberHash equ 0xbcd756f4
ConvertThreadToFiberExHash equ 0xe45d72c7
CopyContextHash equ 0x7701685a
CopyFileAHash equ 0xcfcb9bb0
CopyFileExAHash equ 0x0b538d7d
CopyFileExWHash equ 0x0b538d93
CopyFileTransactedAHash equ 0xb879c6e7
CopyFileTransactedWHash equ 0xb879c6fd
CopyFileWHash equ 0xcfcb9bc6
CopyLZFileHash equ 0x33005bff
CreateActCtxAHash equ 0x703569f0
CreateActCtxWHash equ 0x70356a06
CreateBoundaryDescriptorAHash equ 0xb7e8096c
CreateBoundaryDescriptorWHash equ 0xb7e80982
CreateConsoleScreenBufferHash equ 0x1640bc07
CreateDirectoryAHash equ 0x47f765b0
CreateDirectoryExAHash equ 0x27b4d77d
CreateDirectoryExWHash equ 0x27b4d793
CreateDirectoryTransactedAHash equ 0xabf110e7
CreateDirectoryTransactedWHash equ 0xabf110fd
CreateDirectoryWHash equ 0x47f765c6
CreateEventAHash equ 0x4d881523
CreateEventExAHash equ 0x0bd77630
CreateEventExWHash equ 0x0bd77646
CreateEventWHash equ 0x4d881539
CreateFiberHash equ 0x4498e930
CreateFiberExHash equ 0x82036603
CreateFileAHash equ 0x44990e89
CreateFileMappingAHash equ 0xa481360b
CreateFileMappingNumaAHash equ 0x767f3eb0
CreateFileMappingNumaWHash equ 0x767f3ec6
CreateFileMappingWHash equ 0xa4813621
CreateFileTransactedAHash equ 0x5e7c3e80
CreateFileTransactedWHash equ 0x5e7c3e96
CreateFileWHash equ 0x44990e9f
CreateHardLinkAHash equ 0x42e90ba0
CreateHardLinkTransactedAHash equ 0x6b400ad7
CreateHardLinkTransactedWHash equ 0x6b400aed
CreateHardLinkWHash equ 0x42e90bb6
CreateIoCompletionPortHash equ 0x57fd9a7f
CreateJobObjectAHash equ 0x6f2838a1
CreateJobObjectWHash equ 0x6f2838b7
CreateJobSetHash equ 0x55abe7a1
CreateMailslotAHash equ 0x5bf4dcf0
CreateMailslotWHash equ 0x5bf4dd06
CreateMemoryResourceNotificationHash equ 0xfd2e20f6
CreateMutexAHash equ 0x5b2772de
CreateMutexExAHash equ 0x2f16512b
CreateMutexExWHash equ 0x2f165141
CreateMutexWHash equ 0x5b2772f4
CreateNamedPipeAHash equ 0x29033ed6
CreateNamedPipeWHash equ 0x29033eec
CreatePipeHash equ 0xc86c94ea
CreatePrivateNamespaceAHash equ 0x88319e6d
CreatePrivateNamespaceWHash equ 0x88319e83
CreateProcessAHash equ 0xbf5ac4ee
CreateProcessAsUserWHash equ 0x9063c7a7
CreateProcessInternalAHash equ 0xf200f8b1
CreateProcessInternalWHash equ 0xf200f8c7
CreateProcessWHash equ 0xbf5ac504
CreateRemoteThreadHash equ 0xe2ea3d2c
CreateRemoteThreadExHash equ 0xd14faaff
CreateSemaphoreAHash equ 0x81ba60b9
CreateSemaphoreExAHash equ 0xfca53446
CreateSemaphoreExWHash equ 0xfca5345c
CreateSemaphoreWHash equ 0x81ba60cf
CreateSocketHandleHash equ 0xce07eeb7
CreateSymbolicLinkAHash equ 0xd91dd239
CreateSymbolicLinkTransactedAHash equ 0xaf642630
CreateSymbolicLinkTransactedWHash equ 0xaf642646
CreateSymbolicLinkWHash equ 0xd91dd24f
CreateTapePartitionHash equ 0x3a45742c
CreateThreadHash equ 0x66614246
CreateThreadpoolHash equ 0xf3ff4762
CreateThreadpoolCleanupGroupHash equ 0x888dcebd
CreateThreadpoolIoHash equ 0xf14b0028
CreateThreadpoolTimerHash equ 0x87811d03
CreateThreadpoolWaitHash equ 0xca91cbf7
CreateThreadpoolWorkHash equ 0xca920193
CreateTimerQueueHash equ 0x9cd69b08
CreateTimerQueueTimerHash equ 0x8a8a211d
CreateToolhelp32SnapshotHash equ 0x14b95d18
CreateWaitableTimerAHash equ 0x577eb307
CreateWaitableTimerExAHash equ 0x729e2b14
CreateWaitableTimerExWHash equ 0x729e2b2a
CreateWaitableTimerWHash equ 0x577eb31d
CtrlRoutineHash equ 0x386a5fb9
DeactivateActCtxHash equ 0xeb8ac9e9
DebugActiveProcessHash equ 0x2bfed916
DebugActiveProcessStopHash equ 0xf047da38
DebugBreakHash equ 0x0788aa8c
DebugBreakProcessHash equ 0x972e5643
DebugSetProcessKillOnExitHash equ 0x47c42efb
DecodePointerHash equ 0x16170c4f
DecodeSystemPointerHash equ 0xf5a3d9a0
DefineDosDeviceAHash equ 0xd4820a7e
DefineDosDeviceWHash equ 0xd4820a94
DelayLoadFailureHookHash equ 0xa3485924
DeleteAtomHash equ 0xdff6e1bc
DeleteBoundaryDescriptorHash equ 0x15355c64
DeleteCriticalSectionHash equ 0x65a5b4fb
DeleteFiberHash equ 0x1f2699e1
DeleteFileAHash equ 0x1f26bf3a
DeleteFileTransactedAHash equ 0x59cd85f1
DeleteFileTransactedWHash equ 0x59cd8607
DeleteFileWHash equ 0x1f26bf50
DeleteProcThreadAttributeListHash equ 0xb976bdef
DeleteTimerQueueHash equ 0xd560b0f7
DeleteTimerQueueExHash equ 0xfff8580a
DeleteTimerQueueTimerHash equ 0x85db688e
DeleteVolumeMountPointAHash equ 0x7cfeb825
DeleteVolumeMountPointWHash equ 0x7cfeb83b
DeviceIoControlHash equ 0xf68b7381
DisableThreadLibraryCallsHash equ 0x036871ec
DisableThreadProfilingHash equ 0xb7f83154
DisassociateCurrentThreadFromCallbackHash equ 0xf356c202
DisconnectNamedPipeHash equ 0x488e072b
DnsHostnameToComputerNameAHash equ 0x6ea7a204
DnsHostnameToComputerNameWHash equ 0x6ea7a21a
DosDateTimeToFileTimeHash equ 0xdb47bb47
DosPathToSessionPathAHash equ 0x4824b8ae
DosPathToSessionPathWHash equ 0x4824b8c4
DuplicateConsoleHandleHash equ 0xab50fb34
DuplicateHandleHash equ 0xda512af3
EnableThreadProfilingHash equ 0xb0c6e919
EncodePointerHash equ 0x49d8e327
EncodeSystemPointerHash equ 0xac6f2e78
EndUpdateResourceAHash equ 0x578430ef
EndUpdateResourceWHash equ 0x57843105
EnterCriticalSectionHash equ 0xf31ef86e
EnumCalendarInfoAHash equ 0x8a966114
EnumCalendarInfoExAHash equ 0x3e8289e1
EnumCalendarInfoExExHash equ 0x91ceb333
EnumCalendarInfoExWHash equ 0x3e8289f7
EnumCalendarInfoWHash equ 0x8a96612a
EnumDateFormatsAHash equ 0xf6fa5df4
EnumDateFormatsExAHash equ 0x21dacec1
EnumDateFormatsExExHash equ 0x197f0a53
EnumDateFormatsExWHash equ 0x21daced7
EnumDateFormatsWHash equ 0xf6fa5e0a
EnumLanguageGroupLocalesAHash equ 0xc5e21a8e
EnumLanguageGroupLocalesWHash equ 0xc5e21aa4
EnumResourceLanguagesAHash equ 0xc3a0b135
EnumResourceLanguagesExAHash equ 0x5e3955c2
EnumResourceLanguagesExWHash equ 0x5e3955d8
EnumResourceLanguagesWHash equ 0xc3a0b14b
EnumResourceNamesAHash equ 0xb6b0c728
EnumResourceNamesExAHash equ 0xcd9bbaf5
EnumResourceNamesExWHash equ 0xcd9bbb0b
EnumResourceNamesWHash equ 0xb6b0c73e
EnumResourceTypesAHash equ 0xc2416c17
EnumResourceTypesExAHash equ 0x3796e024
EnumResourceTypesExWHash equ 0x3796e03a
EnumResourceTypesWHash equ 0xc2416c2d
EnumSystemCodePagesAHash equ 0xca06481a
EnumSystemCodePagesWHash equ 0xca064830
EnumSystemFirmwareTablesHash equ 0xeb5c8ed0
EnumSystemGeoIDHash equ 0x9485fb5c
EnumSystemLanguageGroupsAHash equ 0x898829a5
EnumSystemLanguageGroupsWHash equ 0x898829bb
EnumSystemLocalesAHash equ 0xd8edecd8
EnumSystemLocalesExHash equ 0x44cfaf1c
EnumSystemLocalesWHash equ 0xd8edecee
EnumTimeFormatsAHash equ 0x6b383213
EnumTimeFormatsExHash equ 0xfbce1141
EnumTimeFormatsWHash equ 0x6b383229
EnumUILanguagesAHash equ 0xa03f48db
EnumUILanguagesWHash equ 0xa03f48f1
EnumerateLocalComputerNamesAHash equ 0xea16345b
EnumerateLocalComputerNamesWHash equ 0xea163471
EraseTapeHash equ 0x0de898c8
EscapeCommFunctionHash equ 0x77209245
ExitProcessHash equ 0xd6f0c751
ExitThreadHash equ 0x80d3c0e8
ExitVDMHash equ 0x14d12d61
ExpandEnvironmentStringsAHash equ 0xb73f0018
ExpandEnvironmentStringsWHash equ 0xb73f002e
ExpungeConsoleCommandHistoryAHash equ 0x88ac2215
ExpungeConsoleCommandHistoryWHash equ 0x88ac222b
FatalAppExitAHash equ 0xfe80b246
FatalAppExitWHash equ 0xfe80b25c
FatalExitHash equ 0x8af46022
FileTimeToDosDateTimeHash equ 0x3b30f37f
FileTimeToLocalFileTimeHash equ 0xb5a53a70
FileTimeToSystemTimeHash equ 0x4845a7a0
FillConsoleOutputAttributeHash equ 0xcadfc5c7
FillConsoleOutputCharacterAHash equ 0xc326f46d
FillConsoleOutputCharacterWHash equ 0xc326f483
FindActCtxSectionGuidHash equ 0x5ab426c0
FindActCtxSectionStringAHash equ 0xc40212b9
FindActCtxSectionStringWHash equ 0xc40212cf
FindAtomAHash equ 0x8f6e36b7
FindAtomWHash equ 0x8f6e36cd
FindCloseHash equ 0x8f86c39f
FindCloseChangeNotificationHash equ 0xf23f5eba
FindFirstChangeNotificationAHash equ 0x9129190f
FindFirstChangeNotificationWHash equ 0x91291925
FindFirstFileAHash equ 0x79e4b02e
FindFirstFileExAHash equ 0x93797a7b
FindFirstFileExWHash equ 0x93797a91
FindFirstFileNameTransactedWHash equ 0xf875fff0
FindFirstFileNameWHash equ 0x9b79d879
FindFirstFileTransactedAHash equ 0x7dd9d5e5
FindFirstFileTransactedWHash equ 0x7dd9d5fb
FindFirstFileWHash equ 0x79e4b044
FindFirstStreamTransactedWHash equ 0x92ffcb37
FindFirstStreamWHash equ 0x5644c080
FindFirstVolumeAHash equ 0xec221c10
FindFirstVolumeMountPointAHash equ 0xcf36db19
FindFirstVolumeMountPointWHash equ 0xcf36db2f
FindFirstVolumeWHash equ 0xec221c26
FindNLSStringHash equ 0x8538410d
FindNLSStringExHash equ 0x182c3aa0
FindNextChangeNotificationHash equ 0x2a60b647
FindNextFileAHash equ 0x853fd939
FindNextFileNameWHash equ 0xc3b38404
FindNextFileWHash equ 0x853fd94f
FindNextStreamWHash equ 0xf779d2cb
FindNextVolumeAHash equ 0x8d572e5b
FindNextVolumeMountPointAHash equ 0xe5bdcba4
FindNextVolumeMountPointWHash equ 0xe5bdcbba
FindNextVolumeWHash equ 0x8d572e71
FindResourceAHash equ 0xc7e4781a
FindResourceExAHash equ 0x60a6f767
FindResourceExWHash equ 0x60a6f77d
FindResourceWHash equ 0xc7e47830
FindStringOrdinalHash equ 0x576a3bc7
FindVolumeCloseHash equ 0xe1603365
FindVolumeMountPointCloseHash equ 0x0a20506e
FlsAllocHash equ 0x80b746e8
FlsFreeHash equ 0x35b5b059
FlsGetValueHash equ 0xd9671328
FlsSetValueHash equ 0xb7f52d9c
FlushConsoleInputBufferHash equ 0xe89bc4d7
FlushFileBuffersHash equ 0xf8051993
FlushInstructionCacheHash equ 0x202fc298
FlushProcessWriteBuffersHash equ 0x3e3fd9df
FlushViewOfFileHash equ 0xcf4f64fc
FoldStringAHash equ 0xb64482ef
FoldStringWHash equ 0xb6448305
FormatMessageAHash equ 0xa7164251
FormatMessageWHash equ 0xa7164267
FreeConsoleHash equ 0x96033d2b
FreeEnvironmentStringsAHash equ 0x2e7ebb06
FreeEnvironmentStringsWHash equ 0x2e7ebb1c
FreeLibraryHash equ 0x67347c8f
FreeLibraryAndExitThreadHash equ 0x0d9bedb0
FreeLibraryWhenCallbackReturnsHash equ 0xf8bb7595
FreeResourceHash equ 0x37ea66ba
FreeUserPhysicalPagesHash equ 0xf963b1f6
GenerateConsoleCtrlEventHash equ 0xcc49cb0d
GetACPHash equ 0x7eed1178
GetActiveProcessorCountHash equ 0x5ba13c99
GetActiveProcessorGroupCountHash equ 0xb6e25c86
GetApplicationRecoveryCallbackHash equ 0x24ac4754
GetApplicationRestartSettingsHash equ 0x14d723b8
GetAtomNameAHash equ 0xf77bfdaf
GetAtomNameWHash equ 0xf77bfdc5
GetBinaryTypeHash equ 0xe9660eb1
GetBinaryTypeAHash equ 0x435bc7b0
GetBinaryTypeWHash equ 0x435bc7c6
GetCPInfoHash equ 0x8a033971
GetCPInfoExAHash equ 0xad3a96bd
GetCPInfoExWHash equ 0xad3a96d3
GetCalendarDateFormatHash equ 0xa2d4ecf9
GetCalendarDateFormatExHash equ 0x414d9b8c
GetCalendarDaysInMonthHash equ 0xe664ded0
GetCalendarDifferenceInDaysHash equ 0x5c60d36d
GetCalendarInfoAHash equ 0xfeee9d1f
GetCalendarInfoExHash equ 0xdee507b5
GetCalendarInfoWHash equ 0xfeee9d35
GetCalendarMonthsInYearHash equ 0xfaec7d89
GetCalendarSupportedDateRangeHash equ 0x79b3c4d5
GetCalendarWeekNumberHash equ 0x4a86b411
GetComPlusPackageInstallStatusHash equ 0x75f1010c
GetCommConfigHash equ 0x197e8d44
GetCommMaskHash equ 0xbb50a96e
GetCommModemStatusHash equ 0x8b0516fa
GetCommPropertiesHash equ 0x8893c635
GetCommStateHash equ 0xaf21724f
GetCommTimeoutsHash equ 0x5adef0b4
GetCommandLineAHash equ 0x990ea098
GetCommandLineWHash equ 0x990ea0ae
GetCompressedFileSizeAHash equ 0x60db2aad
GetCompressedFileSizeTransactedAHash equ 0x83f47da4
GetCompressedFileSizeTransactedWHash equ 0x83f47dba
GetCompressedFileSizeWHash equ 0x60db2ac3
GetComputerNameAHash equ 0xde7da125
GetComputerNameExAHash equ 0x359a09b2
GetComputerNameExWHash equ 0x359a09c8
GetComputerNameWHash equ 0xde7da13b
GetConsoleAliasAHash equ 0x45a76892
GetConsoleAliasExesAHash equ 0xdc2d4371
GetConsoleAliasExesLengthAHash equ 0xda0bd92b
GetConsoleAliasExesLengthWHash equ 0xda0bd941
GetConsoleAliasExesWHash equ 0xdc2d4387
GetConsoleAliasWHash equ 0x45a768a8
GetConsoleAliasesAHash equ 0x79702164
GetConsoleAliasesLengthAHash equ 0xf57f34de
GetConsoleAliasesLengthWHash equ 0xf57f34f4
GetConsoleAliasesWHash equ 0x7970217a
GetConsoleCPHash equ 0xefcbb96e
GetConsoleCharTypeHash equ 0x68d48c11
GetConsoleCommandHistoryAHash equ 0xd5e6e717
GetConsoleCommandHistoryLengthAHash equ 0xca09a851
GetConsoleCommandHistoryLengthWHash equ 0xca09a867
GetConsoleCommandHistoryWHash equ 0xd5e6e72d
GetConsoleCursorInfoHash equ 0x55d44d45
GetConsoleCursorModeHash equ 0x55d6223a
GetConsoleDisplayModeHash equ 0x29aa1d84
GetConsoleFontInfoHash equ 0x2909b5fe
GetConsoleFontSizeHash equ 0x290e3151
GetConsoleHardwareStateHash equ 0xefd7e3c8
GetConsoleHistoryInfoHash equ 0xd874db61
GetConsoleInputExeNameAHash equ 0x751fae4d
GetConsoleInputExeNameWHash equ 0x751fae63
GetConsoleInputWaitHandleHash equ 0xd5552fe6
GetConsoleKeyboardLayoutNameAHash equ 0xc759fca4
GetConsoleKeyboardLayoutNameWHash equ 0xc759fcba
GetConsoleModeHash equ 0x2bc82284
GetConsoleNlsModeHash equ 0x1f7a7537
GetConsoleOriginalTitleAHash equ 0x414741bb
GetConsoleOriginalTitleWHash equ 0x414741d1
GetConsoleOutputCPHash equ 0x1772758f
GetConsoleProcessListHash equ 0xcf8cfbac
GetConsoleScreenBufferInfoHash equ 0x7b3ef1fb
GetConsoleScreenBufferInfoExHash equ 0xa74a680e
GetConsoleSelectionInfoHash equ 0x1bec2899
GetConsoleTitleAHash equ 0x65ee5d8a
GetConsoleTitleWHash equ 0x65ee5da0
GetConsoleWindowHash equ 0x6b0a1091
GetCurrencyFormatAHash equ 0x505737c3
GetCurrencyFormatExHash equ 0xba8fc191
GetCurrencyFormatWHash equ 0x505737d9
GetCurrentActCtxHash equ 0xf133db78
GetCurrentConsoleFontHash equ 0xdf5288e3
GetCurrentConsoleFontExHash equ 0x54d3e4f6
GetCurrentDirectoryAHash equ 0xa4ab4137
GetCurrentDirectoryWHash equ 0xa4ab414d
GetCurrentProcessHash equ 0x68259b8c
GetCurrentProcessIdHash equ 0xf52cf1c7
GetCurrentProcessorNumberHash equ 0x1cadee98
GetCurrentProcessorNumberExHash equ 0xa8ecb16b
GetCurrentThreadHash equ 0x11e5f94d
GetCurrentThreadIdHash equ 0x304ce348
GetDateFormatAHash equ 0xbcf76286
GetDateFormatExHash equ 0xe1f4ef2e
GetDateFormatWHash equ 0xbcf7629c
GetDefaultCommConfigAHash equ 0x3a42c968
GetDefaultCommConfigWHash equ 0x3a42c97e
GetDevicePowerStateHash equ 0xbb6edcd8
GetDiskFreeSpaceAHash equ 0xd95507da
GetDiskFreeSpaceExAHash equ 0xd8329727
GetDiskFreeSpaceExWHash equ 0xd832973d
GetDiskFreeSpaceWHash equ 0xd95507f0
GetDllDirectoryAHash equ 0x49f543e2
GetDllDirectoryWHash equ 0x49f543f8
GetDriveTypeAHash equ 0x3fb61cb3
GetDriveTypeWHash equ 0x3fb61cc9
GetDurationFormatHash equ 0xb251bf81
GetDurationFormatExHash equ 0x64dfec14
GetDynamicTimeZoneInformationHash equ 0x2ab2ac6a
GetEnabledXStateFeaturesHash equ 0x5b5da661
GetEnvironmentStringsHash equ 0x59c5cec5
GetEnvironmentStringsAHash equ 0xdef40a1c
GetEnvironmentStringsWHash equ 0xdef40a32
GetEnvironmentVariableAHash equ 0x05eaa4c8
GetEnvironmentVariableWHash equ 0x05eaa4de
GetEraNameCountedStringHash equ 0x75f40436
GetErrorModeHash equ 0x1cda0135
GetExitCodeProcessHash equ 0x10f431ae
GetExitCodeThreadHash equ 0xa3bb16eb
GetExpandedNameAHash equ 0xcb4d4647
GetExpandedNameWHash equ 0xcb4d465d
GetFileAttributesAHash equ 0xbcd7bc98
GetFileAttributesExAHash equ 0xe5db1465
GetFileAttributesExWHash equ 0xe5db147b
GetFileAttributesTransactedAHash equ 0x4c1fe5cf
GetFileAttributesTransactedWHash equ 0x4c1fe5e5
GetFileAttributesWHash equ 0xbcd7bcae
GetFileBandwidthReservationHash equ 0x5e2f8f4d
GetFileInformationByHandleHash equ 0x1aa30379
GetFileInformationByHandleExHash equ 0xfdf0120c
GetFileMUIInfoHash equ 0x2a8485dd
GetFileMUIPathHash equ 0x2a878554
GetFileSizeHash equ 0xb36c10f3
GetFileSizeExHash equ 0x88aba906
GetFileTimeHash equ 0xb36c83bf
GetFileTypeHash equ 0xb36cc02c
GetFinalPathNameByHandleAHash equ 0x6d7b1452
GetFinalPathNameByHandleWHash equ 0x6d7b1468
GetFirmwareEnvironmentVariableAHash equ 0x0b243123
GetFirmwareEnvironmentVariableWHash equ 0x0b243139
GetFullPathNameAHash equ 0x56f8c08c
GetFullPathNameTransactedAHash equ 0x091388c3
GetFullPathNameTransactedWHash equ 0x091388d9
GetFullPathNameWHash equ 0x56f8c0a2
GetGeoInfoAHash equ 0x4b5481d8
GetGeoInfoWHash equ 0x4b5481ee
GetHandleContextHash equ 0xe648a2d1
GetHandleInformationHash equ 0xf448814e
GetLargePageMinimumHash equ 0x1a21ef9a
GetLargestConsoleWindowSizeHash equ 0x9062dea2
GetLastErrorHash equ 0x7fca427c
GetLocalTimeHash equ 0xc162be42
GetLocaleInfoAHash equ 0x0eec2e03
GetLocaleInfoExHash equ 0xce999351
GetLocaleInfoWHash equ 0x0eec2e19
GetLogicalDriveStringsAHash equ 0x6ba34076
GetLogicalDriveStringsWHash equ 0x6ba3408c
GetLogicalDrivesHash equ 0x190035fc
GetLogicalProcessorInformationHash equ 0xdbaf11cd
GetLogicalProcessorInformationExHash equ 0xac31db60
GetLongPathNameAHash equ 0x243b373f
GetLongPathNameTransactedAHash equ 0x32237bb6
GetLongPathNameTransactedWHash equ 0x32237bcc
GetLongPathNameWHash equ 0x243b3755
GetMailslotInfoHash equ 0x55063cd9
GetMaximumProcessorCountHash equ 0x79496047
GetMaximumProcessorGroupCountHash equ 0xc4c35598
GetModuleFileNameAHash equ 0x8c957fd8
GetModuleFileNameWHash equ 0x8c957fee
GetModuleHandleAHash equ 0x53147777
GetModuleHandleExAHash equ 0xdfd49384
GetModuleHandleExWHash equ 0xdfd4939a
GetModuleHandleWHash equ 0x5314778d
GetNLSVersionHash equ 0x3feeb879
GetNLSVersionExHash equ 0xff22870c
GetNamedPipeAttributeHash equ 0xeea99bab
GetNamedPipeClientComputerNameAHash equ 0xd0b6c8ff
GetNamedPipeClientComputerNameWHash equ 0xd0b6c915
GetNamedPipeClientProcessIdHash equ 0xe063322e
GetNamedPipeClientSessionIdHash equ 0x45de2895
GetNamedPipeHandleStateAHash equ 0x5b372aa9
GetNamedPipeHandleStateWHash equ 0x5b372abf
GetNamedPipeInfoHash equ 0x9072c63f
GetNamedPipeServerProcessIdHash equ 0x11d35db6
GetNamedPipeServerSessionIdHash equ 0x774e541d
GetNativeSystemInfoHash equ 0xfed5064a
GetNextVDMCommandHash equ 0x60b336f5
GetNumaAvailableMemoryNodeHash equ 0xb179689b
GetNumaAvailableMemoryNodeExHash equ 0x38c1b6ae
GetNumaHighestNodeNumberHash equ 0xb9adf5be
GetNumaNodeNumberFromHandleHash equ 0x2034c04e
GetNumaNodeProcessorMaskHash equ 0x2539fdcb
GetNumaNodeProcessorMaskExHash equ 0xbeb1bfde
GetNumaProcessorNodeHash equ 0xa51e2f43
GetNumaProcessorNodeExHash equ 0xd64f7356
GetNumaProximityNodeHash equ 0x88dbb4b0
GetNumaProximityNodeExHash equ 0xc0c15183
GetNumberFormatAHash equ 0x713c300b
GetNumberFormatExHash equ 0xb649d249
GetNumberFormatWHash equ 0x713c3021
GetNumberOfConsoleFontsHash equ 0x702d0663
GetNumberOfConsoleInputEventsHash equ 0xc0fb2aa2
GetNumberOfConsoleMouseButtonsHash equ 0xf938a5dd
GetOEMCPHash equ 0x78b4c26e
GetOverlappedResultHash equ 0x1debe8fb
GetPhysicallyInstalledSystemMemoryHash equ 0xaa636450
GetPriorityClassHash equ 0xbbbca69e
GetPrivateProfileIntAHash equ 0x7b271bce
GetPrivateProfileIntWHash equ 0x7b271be4
GetPrivateProfileSectionAHash equ 0x3029e598
GetPrivateProfileSectionNamesAHash equ 0x6656d722
GetPrivateProfileSectionNamesWHash equ 0x6656d738
GetPrivateProfileSectionWHash equ 0x3029e5ae
GetPrivateProfileStringAHash equ 0x874fb734
GetPrivateProfileStringWHash equ 0x874fb74a
GetPrivateProfileStructAHash equ 0x875503f0
GetPrivateProfileStructWHash equ 0x87550406
GetProcAddressHash equ 0x1f7056a8
GetProcessAffinityMaskHash equ 0xdd969d2d
GetProcessDEPPolicyHash equ 0xf35c87c8
GetProcessGroupAffinityHash equ 0x620566ee
GetProcessHandleCountHash equ 0x6adabbae
GetProcessHeapHash equ 0xaa29a3e5
GetProcessHeapsHash equ 0x9b0ad92e
GetProcessIdHash equ 0xc7f80d54
GetProcessIdOfThreadHash equ 0x278de835
GetProcessIoCountersHash equ 0xbcae0c76
GetProcessPreferredUILanguagesHash equ 0xbfc020bf
GetProcessPriorityBoostHash equ 0xf421f286
GetProcessShutdownParametersHash equ 0x74e09f19
GetProcessTimesHash equ 0x9bb5f06d
GetProcessUserModeExceptionPolicyHash equ 0xbc03d5da
GetProcessVersionHash equ 0xe941583f
GetProcessWorkingSetSizeHash equ 0x4d6825cb
GetProcessWorkingSetSizeExHash equ 0x93f5e7de
GetProcessorSystemCycleTimeHash equ 0x658f1dc8
GetProductInfoHash equ 0x452fa927
GetProfileIntAHash equ 0xa8af7a65
GetProfileIntWHash equ 0xa8af7a7b
GetProfileSectionAHash equ 0x8ea320af
GetProfileSectionWHash equ 0x8ea320c5
GetProfileStringAHash equ 0x37c73d3d
GetProfileStringWHash equ 0x37c73d53
GetQueuedCompletionStatusHash equ 0xd4af2957
GetQueuedCompletionStatusExHash equ 0x658a386a
GetShortPathNameAHash equ 0xea5645ab
GetShortPathNameWHash equ 0xea5645c1
GetStartupInfoAHash equ 0xaad94f2c
GetStartupInfoWHash equ 0xaad94f42
GetStdHandleHash equ 0xe0557795
GetStringScriptsHash equ 0x03837c21
GetStringTypeAHash equ 0x437e7da0
GetStringTypeExAHash equ 0x5dd5b36d
GetStringTypeExWHash equ 0x5dd5b383
GetStringTypeWHash equ 0x437e7db6
GetSystemDEPPolicyHash equ 0x4d08ca9c
GetSystemDefaultLCIDHash equ 0x98f96c4e
GetSystemDefaultLangIDHash equ 0x4207b025
GetSystemDefaultLocaleNameHash equ 0x3e146aa1
GetSystemDefaultUILanguageHash equ 0x80dd7c88
GetSystemDirectoryAHash equ 0x3c747e59
GetSystemDirectoryWHash equ 0x3c747e6f
GetSystemFileCacheSizeHash equ 0xccf59382
GetSystemFirmwareTableHash equ 0x1df979ce
GetSystemInfoHash equ 0x442c8353
GetSystemPowerStatusHash equ 0xcd4ebb12
GetSystemPreferredUILanguagesHash equ 0x0e53916b
GetSystemRegistryQuotaHash equ 0x7d024736
GetSystemTimeHash equ 0x44317172
GetSystemTimeAdjustmentHash equ 0xa859947f
GetSystemTimeAsFileTimeHash equ 0x351663cd
GetSystemTimesHash equ 0x41fcbd41
GetSystemWindowsDirectoryAHash equ 0x1d82bbd2
GetSystemWindowsDirectoryWHash equ 0x1d82bbe8
GetSystemWow64DirectoryAHash equ 0xbd394b2c
GetSystemWow64DirectoryWHash equ 0xbd394b42
GetTapeParametersHash equ 0x3f9d5d82
GetTapePositionHash equ 0x9c3a3ac1
GetTapeStatusHash equ 0xe2a0f78a
GetTempFileNameAHash equ 0x151fe9f0
GetTempFileNameWHash equ 0x151fea06
GetTempPathAHash equ 0x7dccf6b2
GetTempPathWHash equ 0x7dccf6c8
GetThreadContextHash equ 0xcb52c0af
GetThreadErrorModeHash equ 0x6d8606cb
GetThreadGroupAffinityHash equ 0x92f6dfc7
GetThreadIOPendingFlagHash equ 0xcdd5ffbd
GetThreadIdHash equ 0x3719a21b
GetThreadIdealProcessorExHash equ 0xd55a3e50
GetThreadLocaleHash equ 0xf4dd235a
GetThreadPreferredUILanguagesHash equ 0x6896b1c6
GetThreadPriorityHash equ 0x7b5e4ea4
GetThreadPriorityBoostHash equ 0x25136b5f
GetThreadSelectorEntryHash equ 0x72ca02d3
GetThreadTimesHash equ 0x10965246
GetThreadUILanguageHash equ 0x7375e6ec
GetTickCountHash equ 0x031a4edc
GetTickCount64Hash equ 0xa5c20e9a
GetTimeFormatAHash equ 0x9faf0e87
GetTimeFormatExHash equ 0x5632c34d
GetTimeFormatWHash equ 0x9faf0e9d
GetTimeZoneInformationHash equ 0x93d3903d
GetTimeZoneInformationForYearHash equ 0xad80b5a9
GetUILanguageInfoHash equ 0xa42d6190
GetUserDefaultLCIDHash equ 0xaa35ebb2
GetUserDefaultLangIDHash equ 0xf621e689
GetUserDefaultLocaleNameHash equ 0x53a4cf05
GetUserDefaultUILanguageHash equ 0x966de0ec
GetUserGeoIDHash equ 0x1c1c988b
GetUserPreferredUILanguagesHash equ 0x7c662287
GetVDMCurrentDirectoriesHash equ 0x9b7a30db
GetVersionHash equ 0xc99434c2
GetVersionExAHash equ 0xf5e88dcc
GetVersionExWHash equ 0xf5e88de2
GetVolumeInformationAHash equ 0xd45846a5
GetVolumeInformationByHandleWHash equ 0x7d04651c
GetVolumeInformationWHash equ 0xd45846bb
GetVolumeNameForVolumeMountPointAHash equ 0x6d62b222
GetVolumeNameForVolumeMountPointWHash equ 0x6d62b238
GetVolumePathNameAHash equ 0xf63c75e1
GetVolumePathNameWHash equ 0xf63c75f7
GetVolumePathNamesForVolumeNameAHash equ 0xf45d7886
GetVolumePathNamesForVolumeNameWHash equ 0xf45d789c
GetWindowsDirectoryAHash equ 0x9f03e1c1
GetWindowsDirectoryWHash equ 0x9f03e1d7
GetWriteWatchHash equ 0xf77c7806
GetXStateFeaturesMaskHash equ 0xd305b038
GlobalAddAtomAHash equ 0x6e9a05d2
GlobalAddAtomWHash equ 0x6e9a05e8
GlobalAllocHash equ 0x2f972532
GlobalCompactHash equ 0x155c31e0
GlobalDeleteAtomHash equ 0x501a39bf
GlobalFindAtomAHash equ 0x9b4e5254
GlobalFindAtomWHash equ 0x9b4e526a
GlobalFixHash equ 0x8e916952
GlobalFlagsHash equ 0x2fdd7084
GlobalFreeHash equ 0x439be0cf
GlobalGetAtomNameAHash equ 0xec2960f2
GlobalGetAtomNameWHash equ 0xec296108
GlobalHandleHash equ 0xcea52bcb
GlobalLockHash equ 0x439e8f8e
GlobalMemoryStatusHash equ 0x2792abb6
GlobalMemoryStatusExHash equ 0x8d969f09
GlobalReAllocHash equ 0x1b5b837f
GlobalSizeHash equ 0x43a1aa64
GlobalUnWireHash equ 0xe580fc61
GlobalUnfixHash equ 0x30b1ccd9
GlobalUnlockHash equ 0xe58a9ce7
GlobalWireHash equ 0x43a37ae8
Heap32FirstHash equ 0xc4f99805
Heap32ListFirstHash equ 0xac92f787
Heap32ListNextHash equ 0xa27bef3c
Heap32NextHash equ 0x0ea046fe
HeapAllocHash equ 0x7d37d889
HeapCompactHash equ 0x7d9d6b77
HeapCreateHash equ 0x2d7e1628
HeapDestroyHash equ 0xa1c9d04e
HeapFreeHash equ 0xc1fbe698
HeapLockHash equ 0xc1fe9557
HeapQueryInformationHash equ 0x4e542570
HeapReAllocHash equ 0x839cbd16
HeapSetInformationHash equ 0x8e28b896
HeapSizeHash equ 0xc201b02d
HeapSummaryHash equ 0xd63cd7fa
HeapUnlockHash equ 0x4c005470
HeapValidateHash equ 0x0518f342
HeapWalkHash equ 0xc20361f5
IdnToAsciiHash equ 0x532d0383
IdnToNameprepUnicodeHash equ 0xdd866237
IdnToUnicodeHash equ 0x55c08a8f
InitAtomTableHash equ 0x7ad039ad
InitOnceBeginInitializeHash equ 0x3ed64908
InitOnceCompleteHash equ 0xd7d3882a
InitOnceExecuteOnceHash equ 0xbdd33f05
InitOnceInitializeHash equ 0x85402a41
InitializeConditionVariableHash equ 0x53f846e7
InitializeContextHash equ 0x21a71fdf
InitializeCriticalSectionHash equ 0xecde5876
InitializeCriticalSectionAndSpinCountHash equ 0xdc4ab56c
InitializeCriticalSectionExHash equ 0x2eaa1bc9
InitializeProcThreadAttributeListHash equ 0x583db66a
InitializeSListHeadHash equ 0x5b65d361
InitializeSRWLockHash equ 0x3d382173
InterlockedCompareExchangeHash equ 0x9f066282
InterlockedCompareExchange64Hash equ 0xf6f7d0c0
InterlockedDecrementHash equ 0xd659806d
InterlockedExchangeHash equ 0x5b52f709
InterlockedExchangeAddHash equ 0x7bbac0d8
InterlockedFlushSListHash equ 0x71a89273
InterlockedIncrementHash equ 0x629a3f49
InterlockedPopEntrySListHash equ 0xfbbc066a
InterlockedPushEntrySListHash equ 0x8a76c97f
InterlockedPushListSListHash equ 0x5338ca93
InvalidateConsoleDIBitsHash equ 0xa7f40da7
IsBadCodePtrHash equ 0x6c92f6e6
IsBadHugeReadPtrHash equ 0x19416af2
IsBadHugeWritePtrHash equ 0xd4941855
IsBadReadPtrHash equ 0x74d53e9d
IsBadStringPtrAHash equ 0xc0acf37f
IsBadStringPtrWHash equ 0xc0acf395
IsBadWritePtrHash equ 0xeb7aba0a
IsCalendarLeapDayHash equ 0x54311f4c
IsCalendarLeapMonthHash equ 0x0ceb9230
IsCalendarLeapYearHash equ 0x31fc628d
IsDBCSLeadByteHash equ 0x5d7ed05c
IsDBCSLeadByteExHash equ 0xf90c322f
IsDebuggerPresentHash equ 0x652f16b0
IsNLSDefinedStringHash equ 0xc4f0286f
IsNormalizedStringHash equ 0xec91f352
IsProcessInJobHash equ 0x0c7d2593
IsProcessorFeaturePresentHash equ 0xbddb216d
IsSystemResumeAutomaticHash equ 0xaa750725
IsThreadAFiberHash equ 0x5139421f
IsThreadpoolTimerSetHash equ 0x49fc710d
IsTimeZoneRedirectionEnabledHash equ 0x40cf07d8
IsValidCalDateTimeHash equ 0xbf026157
IsValidCodePageHash equ 0xddf90d0e
IsValidLanguageGroupHash equ 0x5ef30a55
IsValidLocaleHash equ 0x66f669cc
IsValidLocaleNameHash equ 0xcef99277
IsWow64ProcessHash equ 0xf8b8f27c
K32EmptyWorkingSetHash equ 0xb71beb54
K32EnumDeviceDriversHash equ 0x80706fca
K32EnumPageFilesAHash equ 0x12102a84
K32EnumPageFilesWHash equ 0x12102a9a
K32EnumProcessModulesHash equ 0x081ad703
K32EnumProcessModulesExHash equ 0x6cc12b16
K32EnumProcessesHash equ 0xf765a392
K32GetDeviceDriverBaseNameAHash equ 0xd4fa8a9b
K32GetDeviceDriverBaseNameWHash equ 0xd4fa8ab1
K32GetDeviceDriverFileNameAHash equ 0xf2ca0ed0
K32GetDeviceDriverFileNameWHash equ 0xf2ca0ee6
K32GetMappedFileNameAHash equ 0x34eaf15b
K32GetMappedFileNameWHash equ 0x34eaf171
K32GetModuleBaseNameAHash equ 0x701ab50d
K32GetModuleBaseNameWHash equ 0x701ab523
K32GetModuleFileNameExAHash equ 0xbc410e8f
K32GetModuleFileNameExWHash equ 0xbc410ea5
K32GetModuleInformationHash equ 0x59c83d74
K32GetPerformanceInfoHash equ 0x45fc9852
K32GetProcessImageFileNameAHash equ 0x36b2c082
K32GetProcessImageFileNameWHash equ 0x36b2c098
K32GetProcessMemoryInfoHash equ 0xc88deb72
K32GetWsChangesHash equ 0x1682129b
K32GetWsChangesExHash equ 0x7e47e0ae
K32InitializeProcessForWsWatchHash equ 0xcfac9e1f
K32QueryWorkingSetHash equ 0xad4ea10f
K32QueryWorkingSetExHash equ 0x942aa222
LCIDToLocaleNameHash equ 0x1904c6d2
LCMapStringAHash equ 0x4e2fd22b
LCMapStringExHash equ 0x77ca7429
LCMapStringWHash equ 0x4e2fd241
LZCloseHash equ 0x51d0ad0a
LZCloseFileHash equ 0x706081a6
LZCopyHash equ 0x86c4b623
LZCreateFileWHash equ 0xc7f32051
LZDoneHash equ 0x86c52a30
LZInitHash equ 0x86c76bbe
LZOpenFileAHash equ 0xe7eef82d
LZOpenFileWHash equ 0xe7eef843
LZReadHash equ 0x86cb6044
LZSeekHash equ 0x86cbd526
LZStartHash equ 0x52b59374
LeaveCriticalSectionHash equ 0x5d9a16af
LeaveCriticalSectionWhenCallbackReturnsHash equ 0x25666775
LoadAppInitDllsHash equ 0x9d4ec59a
LoadLibraryAHash equ 0x896caa0c
LoadLibraryExAHash equ 0xe0ea74d9
LoadLibraryExWHash equ 0xe0ea74ef
LoadLibraryWHash equ 0x896caa22
LoadModuleHash equ 0x5f6b6f12
LoadResourceHash equ 0x41fbfb34
LoadStringBaseExWHash equ 0x28c9d0bc
LoadStringBaseWHash equ 0x051a952f
LocalAllocHash equ 0xc2dc9aaa
LocalCompactHash equ 0xed1a2958
LocalFileTimeToFileTimeHash equ 0x73e43ff8
LocalFlagsHash equ 0xc322e5fc
LocalFreeHash equ 0x2f95dc57
LocalHandleHash equ 0xa40e6553
LocalLockHash equ 0x2f988b16
LocalReAllocHash equ 0xf3197af7
LocalShrinkHash equ 0xb7383d34
LocalSizeHash equ 0x2f9ba5ec
LocalUnlockHash equ 0xbaf3d66f
LocaleNameToLCIDHash equ 0xeea28252
LocateXStateFeatureHash equ 0x9e84776b
LockFileHash equ 0x75a20567
LockFileExHash equ 0x9536507a
LockResourceHash equ 0x386de679
MapUserPhysicalPagesHash equ 0x48c7c546
MapUserPhysicalPagesScatterHash equ 0x1d953e98
MapViewOfFileHash equ 0xcbee3954
MapViewOfFileExHash equ 0x89453d27
MapViewOfFileExNumaHash equ 0xbca98b62
Module32FirstHash equ 0x4e47b785
Module32FirstWHash equ 0x7aaf3972
Module32NextHash equ 0x1b50377e
Module32NextWHash equ 0x4eb6b899
MoveFileAHash equ 0xb5bc68d4
MoveFileExAHash equ 0x3845a1a1
MoveFileExWHash equ 0x3845a1b7
MoveFileTransactedAHash equ 0x05b7770b
MoveFileTransactedWHash equ 0x05b77721
MoveFileWHash equ 0xb5bc68ea
MoveFileWithProgressAHash equ 0x552dc581
MoveFileWithProgressWHash equ 0x552dc597
MulDivHash equ 0x8a080a4d
MultiByteToWideCharHash equ 0x1f8fc105
NeedCurrentDirectoryForExePathAHash equ 0xd6dd9189
NeedCurrentDirectoryForExePathWHash equ 0xd6dd919f
NlsCheckPolicyHash equ 0x7179aec5
NlsEventDataDescCreateHash equ 0x1c7486dc
NlsGetCacheUpdateCountHash equ 0x1bd6bbc5
NlsUpdateLocaleHash equ 0x94c86778
NlsUpdateSystemLocaleHash equ 0xf1055807
NlsWriteEtwEventHash equ 0x9e735e7c
NormalizeStringHash equ 0x0b15255e
NotifyMountMgrHash equ 0x30c43dc8
NotifyUILanguageChangeHash equ 0x54b20645
OpenConsoleWHash equ 0x7c41ba6a
OpenEventAHash equ 0x73cb6ff1
OpenEventWHash equ 0x73cb7007
OpenFileHash equ 0xe5bfbf06
OpenFileByIdHash equ 0x723c9bf8
OpenFileMappingAHash equ 0x4e9cbe59
OpenFileMappingWHash equ 0x4e9cbe6f
OpenJobObjectAHash equ 0xbb857c6f
OpenJobObjectWHash equ 0xbb857c85
OpenMutexAHash equ 0x816acdac
OpenMutexWHash equ 0x816acdc2
OpenPrivateNamespaceAHash equ 0x8f2516df
OpenPrivateNamespaceWHash equ 0x8f2516f5
OpenProcessHash equ 0x453b70a5
OpenProcessTokenHash equ 0x04cdf854
OpenProfileUserMappingHash equ 0x8cd2f524
OpenSemaphoreAHash equ 0xce17a487
OpenSemaphoreWHash equ 0xce17a49d
OpenThreadHash equ 0x8ca49d14
OpenThreadTokenHash equ 0xc9aa3945
OpenWaitableTimerAHash equ 0xe8d95fd5
OpenWaitableTimerWHash equ 0xe8d95feb
OutputDebugStringAHash equ 0x29f1203e
OutputDebugStringWHash equ 0x29f12054
PeekConsoleInputAHash equ 0x06cf2033
PeekConsoleInputWHash equ 0x06cf2049
PeekNamedPipeHash equ 0x2c28bd4c
PostQueuedCompletionStatusHash equ 0xd83afb61
PowerClearRequestHash equ 0x64db5107
PowerCreateRequestHash equ 0x4136090e
PowerSetRequestHash equ 0xa2f0d692
PrepareTapeHash equ 0x152b82a9
PrivCopyFileExWHash equ 0x14486f64
PrivMoveFileIdentityWHash equ 0xb2b66ddd
Process32FirstHash equ 0x3f3a6262
Process32FirstWHash equ 0xa811ea35
Process32NextHash equ 0x441e3d01
Process32NextWHash equ 0x3fa96376
ProcessIdToSessionIdHash equ 0x9f73c7ec
PulseEventHash equ 0x61029aa1
PurgeCommHash equ 0x13452637
QueryActCtxSettingsWHash equ 0x6ce58e17
QueryActCtxWHash equ 0x1a83f8fa
QueryDepthSListHash equ 0x13358d76
QueryDosDeviceAHash equ 0x2736110b
QueryDosDeviceWHash equ 0x27361121
QueryFullProcessImageNameAHash equ 0x93fe27b3
QueryFullProcessImageNameWHash equ 0x93fe27c9
QueryIdleProcessorCycleTimeHash equ 0xa04aea1d
QueryIdleProcessorCycleTimeExHash equ 0xb938dfb0
QueryInformationJobObjectHash equ 0x98ddde58
QueryMemoryResourceNotificationHash equ 0xef492582
QueryPerformanceCounterHash equ 0x86b95274
QueryPerformanceFrequencyHash equ 0x68e843d4
QueryProcessAffinityUpdateModeHash equ 0x8daa8e5b
QueryProcessCycleTimeHash equ 0x172967ec
QueryThreadCycleTimeHash equ 0xcf7ae421
QueryThreadProfilingHash equ 0xf09d4774
QueryThreadpoolStackInformationHash equ 0xc11f8192
QueryUnbiasedInterruptTimeHash equ 0x1627ce97
QueueUserAPCHash equ 0xf6452818
QueueUserWorkItemHash equ 0x431db640
RaiseExceptionHash equ 0xf404bde3
RaiseFailFastExceptionHash equ 0x00743269
ReOpenFileHash equ 0xa445c659
ReadConsoleAHash equ 0x91b0e1a0
ReadConsoleInputAHash equ 0x13a4afd8
ReadConsoleInputExAHash equ 0xbd3837a5
ReadConsoleInputExWHash equ 0xbd3837bb
ReadConsoleInputWHash equ 0x13a4afee
ReadConsoleOutputAHash equ 0xaa7ebd5f
ReadConsoleOutputAttributeHash equ 0xaab0899a
ReadConsoleOutputCharacterAHash equ 0xdd6eaafa
ReadConsoleOutputCharacterWHash equ 0xdd6eab10
ReadConsoleOutputWHash equ 0xaa7ebd75
ReadConsoleWHash equ 0x91b0e1b6
ReadDirectoryChangesWHash equ 0xb328906b
ReadFileHash equ 0xd01e6c52
ReadFileExHash equ 0x4234a8a5
ReadFileScatterHash equ 0x8c52d20c
ReadProcessMemoryHash equ 0x8f14d23a
ReadThreadProfilingDataHash equ 0x916fc570
RegCloseKeyHash equ 0xfec0d5db
RegCreateKeyExAHash equ 0x325e49bf
RegCreateKeyExWHash equ 0x325e49d5
RegDeleteKeyExAHash equ 0xa986af2e
RegDeleteKeyExWHash equ 0xa986af44
RegDeleteTreeAHash equ 0xab25b464
RegDeleteTreeWHash equ 0xab25b47a
RegDeleteValueAHash equ 0xbc0e690f
RegDeleteValueWHash equ 0xbc0e6925
RegDisablePredefinedCacheExHash equ 0xf6c5597b
RegEnumKeyExAHash equ 0x69f8fb04
RegEnumKeyExWHash equ 0x69f8fb1a
RegEnumValueAHash equ 0x7c80b4e5
RegEnumValueWHash equ 0x7c80b4fb
RegFlushKeyHash equ 0x40a2cd4f
RegGetKeySecurityHash equ 0x87b0231d
RegGetValueAHash equ 0x2a1ce1d2
RegGetValueWHash equ 0x2a1ce1e8
RegKrnGetGlobalStateHash equ 0x890d672b
RegKrnInitializeHash equ 0x87071ec3
RegLoadKeyAHash equ 0x2b9b745c
RegLoadKeyWHash equ 0x2b9b7472
RegLoadMUIStringAHash equ 0xcf9f7669
RegLoadMUIStringWHash equ 0xcf9f767f
RegNotifyChangeKeyValueHash equ 0xf993105f
RegOpenCurrentUserHash equ 0x06744926
RegOpenKeyExAHash equ 0xd433b18d
RegOpenKeyExWHash equ 0xd433b1a3
RegOpenUserClassesRootHash equ 0xa0db489f
RegQueryInfoKeyAHash equ 0x39e48064
RegQueryInfoKeyWHash equ 0x39e4807a
RegQueryValueExAHash equ 0xdb3fbf91
RegQueryValueExWHash equ 0xdb3fbfa7
RegRestoreKeyAHash equ 0x0245d45c
RegRestoreKeyWHash equ 0x0245d472
RegSaveKeyExAHash equ 0xff32da80
RegSaveKeyExWHash equ 0xff32da96
RegSetKeySecurityHash equ 0x1e159691
RegSetValueExAHash equ 0x1124342b
RegSetValueExWHash equ 0x11243441
RegUnLoadKeyAHash equ 0x9ab46915
RegUnLoadKeyWHash equ 0x9ab4692b
RegisterApplicationRecoveryCallbackHash equ 0x5282fba7
RegisterApplicationRestartHash equ 0x7f3fdac2
RegisterConsoleIMEHash equ 0xa9f9ba0d
RegisterConsoleOS2Hash equ 0xa9f9d13a
RegisterConsoleVDMHash equ 0xa9f9e9cb
RegisterWaitForInputIdleHash equ 0xbc5f4aed
RegisterWaitForSingleObjectHash equ 0xdb3e6718
RegisterWaitForSingleObjectExHash equ 0x054109eb
RegisterWowBaseHandlersHash equ 0xa33ead56
RegisterWowExecHash equ 0x16fc858d
ReleaseActCtxHash equ 0xcc01d2fc
ReleaseMutexHash equ 0x93a919d8
ReleaseMutexWhenCallbackReturnsHash equ 0xbd65d9ac
ReleaseSRWLockExclusiveHash equ 0xf51f78a2
ReleaseSRWLockSharedHash equ 0x1962d0e1
ReleaseSemaphoreHash equ 0x8581721d
ReleaseSemaphoreWhenCallbackReturnsHash equ 0x1cdd4947
RemoveDirectoryAHash equ 0x18daf338
RemoveDirectoryTransactedAHash equ 0x0d07546f
RemoveDirectoryTransactedWHash equ 0x0d075485
RemoveDirectoryWHash equ 0x18daf34e
RemoveDllDirectoryHash equ 0x29a35cad
RemoveLocalAlternateComputerNameAHash equ 0x96103c68
RemoveLocalAlternateComputerNameWHash equ 0x96103c7e
RemoveSecureMemoryCacheCallbackHash equ 0x895d5d2b
RemoveVectoredContinueHandlerHash equ 0x08cde9dd
RemoveVectoredExceptionHandlerHash equ 0x8452be01
ReplaceFileHash equ 0x7d074a30
ReplaceFileAHash equ 0x23e1fc11
ReplaceFileWHash equ 0x23e1fc27
ReplacePartitionUnitHash equ 0x7cb4915a
RequestDeviceWakeupHash equ 0xf696e944
RequestWakeupLatencyHash equ 0xd8569a90
ResetEventHash equ 0x11783aab
ResetWriteWatchHash equ 0xdaca2abf
ResolveLocaleNameHash equ 0xcfde66f1
RestoreLastErrorHash equ 0x31260e44
ResumeThreadHash equ 0x646180b7
RtlCaptureContextHash equ 0x8aedb073
RtlCaptureStackBackTraceHash equ 0xa6b14bb2
RtlFillMemoryHash equ 0xfc607a4e
RtlMoveMemoryHash equ 0xc07d4e1c
RtlUnwindHash equ 0x7866990b
RtlZeroMemoryHash equ 0xcf0553b3
ScrollConsoleScreenBufferAHash equ 0x0f62f86b
ScrollConsoleScreenBufferWHash equ 0x0f62f881
SearchPathAHash equ 0x4269bbd4
SearchPathWHash equ 0x4269bbea
SetCalendarInfoAHash equ 0x91c50393
SetCalendarInfoWHash equ 0x91c503a9
SetClientDynamicTimeZoneInformationHash equ 0xb2a00921
SetClientTimeZoneInformationHash equ 0xa7bf0366
SetComPlusPackageInstallStatusHash equ 0x7e090c80
SetCommBreakHash equ 0x0a84c731
SetCommConfigHash equ 0x47a2db50
SetCommMaskHash equ 0xb6090a7a
SetCommStateHash equ 0x0b7532c3
SetCommTimeoutsHash equ 0x9127ebc0
SetComputerNameAHash equ 0x71540799
SetComputerNameExAHash equ 0x6c70a326
SetComputerNameExWHash equ 0x6c70a33c
SetComputerNameWHash equ 0x715407af
SetConsoleActiveScreenBufferHash equ 0xf1415d87
SetConsoleCPHash equ 0x4c1f79e2
SetConsoleCtrlHandlerHash equ 0x065eb86a
SetConsoleCursorHash equ 0xdc6aae6b
SetConsoleCursorInfoHash equ 0x316a59b9
SetConsoleCursorModeHash equ 0x316c2eae
SetConsoleCursorPositionHash equ 0x7ee410b4
SetConsoleDisplayModeHash equ 0xc0d59f90
SetConsoleFontHash equ 0xc22a68a4
SetConsoleHardwareStateHash equ 0x6a2b12d4
SetConsoleHistoryInfoHash equ 0x6fa05d6d
SetConsoleIconHash equ 0xc22b98ce
SetConsoleInputExeNameAHash equ 0xef72dd59
SetConsoleInputExeNameWHash equ 0xef72dd6f
SetConsoleKeyShortcutsHash equ 0x656020a3
SetConsoleLocalEUDCHash equ 0xb14de7e5
SetConsoleMaximumWindowSizeHash equ 0x67f9381c
SetConsoleMenuCloseHash equ 0x9c9c6ca4
SetConsoleModeHash equ 0xc22d95f8
SetConsoleNlsModeHash equ 0xe770dd43
SetConsoleNumberOfCommandsAHash equ 0xde1b2564
SetConsoleNumberOfCommandsWHash equ 0xde1b257a
SetConsoleOS2OemFormatHash equ 0x0ddd0c35
SetConsoleOutputCPHash equ 0x4e490f03
SetConsolePaletteHash equ 0x3e205e06
SetConsoleScreenBufferInfoExHash equ 0xf116c082
SetConsoleScreenBufferSizeHash equ 0x917352c2
SetConsoleTextAttributeHash equ 0x6979bb3a
SetConsoleTitleAHash equ 0xf8c4c3fe
SetConsoleTitleWHash equ 0xf8c4c414
SetConsoleWindowInfoHash equ 0x9b364553
SetCriticalSectionSpinCountHash equ 0xcb15b4a9
SetCurrentConsoleFontExHash equ 0xcf271402
SetCurrentDirectoryAHash equ 0x80414dab
SetCurrentDirectoryWHash equ 0x80414dc1
SetDefaultCommConfigAHash equ 0xd16e4b74
SetDefaultCommConfigWHash equ 0xd16e4b8a
SetDefaultDllDirectoriesHash equ 0xb585b9c6
SetDllDirectoryAHash equ 0xdccbaa56
SetDllDirectoryWHash equ 0xdccbaa6c
SetDynamicTimeZoneInformationHash equ 0x1a716276
SetEndOfFileHash equ 0xbdca5e8c
SetEnvironmentStringsAHash equ 0x2d38c990
SetEnvironmentStringsWHash equ 0x2d38c9a6
SetEnvironmentVariableAHash equ 0x803dd3d4
SetEnvironmentVariableWHash equ 0x803dd3ea
SetErrorModeHash equ 0x792dc1a9
SetEventHash equ 0x56cc9778
SetEventWhenCallbackReturnsHash equ 0x3435380c
SetFileApisToANSIHash equ 0x498b0eb5
SetFileApisToOEMHash equ 0x12e3a785
SetFileAttributesAHash equ 0xf3ae560c
SetFileAttributesTransactedAHash equ 0x95ec3e43
SetFileAttributesTransactedWHash equ 0x95ec3e59
SetFileAttributesWHash equ 0xf3ae5622
SetFileBandwidthReservationHash equ 0x0dfc5859
SetFileCompletionNotificationModesHash equ 0x389f7ccb
SetFileInformationByHandleHash equ 0x30d2e8ed
SetFileIoOverlappedRangeHash equ 0x1eab0b71
SetFilePointerHash equ 0x8dce837f
SetFilePointerExHash equ 0x543ba892
SetFileShortNameAHash equ 0x43cb6b78
SetFileShortNameWHash equ 0x43cb6b8e
SetFileTimeHash equ 0xae24e4cb
SetFileValidDataHash equ 0xb4bf9288
SetFirmwareEnvironmentVariableAHash equ 0x060d942f
SetFirmwareEnvironmentVariableWHash equ 0x060d9445
SetHandleContextHash equ 0x791f0945
SetHandleCountHash equ 0x8bfb1225
SetHandleInformationHash equ 0xcfde8dc2
SetInformationJobObjectHash equ 0x4d9b28f2
SetLastConsoleEventActiveHash equ 0x73116081
SetLastErrorHash equ 0xdc1e02f0
SetLocalPrimaryComputerNameAHash equ 0xb6034fc2
SetLocalPrimaryComputerNameWHash equ 0xb6034fd8
SetLocalTimeHash equ 0x1db67eb6
SetLocaleInfoAHash equ 0xa551a177
SetLocaleInfoWHash equ 0xa551a18d
SetMailslotInfoHash equ 0x8b4f37e5
SetMessageWaitingIndicatorHash equ 0x07524dc7
SetNamedPipeAttributeHash equ 0x85d51db7
SetNamedPipeHandleStateHash equ 0xcfd917a4
SetPriorityClassHash equ 0x4e930d12
SetProcessAffinityMaskHash equ 0x2bdb5ca1
SetProcessAffinityUpdateModeHash equ 0x9475d401
SetProcessDEPPolicyHash equ 0x97591cd4
SetProcessPreferredUILanguagesHash equ 0xc7d82c33
SetProcessPriorityBoostHash equ 0x6e752192
SetProcessShutdownParametersHash equ 0xbeacf78d
SetProcessUserModeExceptionPolicyHash equ 0xa220a5e6
SetProcessWorkingSetSizeHash equ 0x1d7ad83f
SetProcessWorkingSetSizeExHash equ 0xaa25cd52
SetSearchPathModeHash equ 0x6b6b8e12
SetStdHandleHash equ 0x3ca93809
SetStdHandleExHash equ 0xb73b629c
SetSystemFileCacheSizeHash equ 0x1b3a52f6
SetSystemPowerStateHash equ 0xecac8a7d
SetSystemTimeHash equ 0x7255bf7e
SetSystemTimeAdjustmentHash equ 0x22acc38b
SetTapeParametersHash equ 0x0793c58e
SetTapePositionHash equ 0xd28335cd
SetTermsrvAppInstallModeHash equ 0xc99e64c6
SetThreadAffinityMaskHash equ 0x23c1a740
SetThreadContextHash equ 0x5e292723
SetThreadErrorModeHash equ 0xa45ca03f
SetThreadExecutionStateHash equ 0xbe673c65
SetThreadGroupAffinityHash equ 0xe13b9f3b
SetThreadIdealProcessorHash equ 0x9ec69fc9
SetThreadIdealProcessorExHash equ 0x079dda5c
SetThreadLocaleHash equ 0x2b261e66
SetThreadPreferredUILanguagesHash equ 0x585567d2
SetThreadPriorityHash equ 0x4354b6b0
SetThreadPriorityBoostHash equ 0x73582ad3
SetThreadStackGuaranteeHash equ 0xa65cb8ec
SetThreadTokenHash equ 0xa6fe786d
SetThreadUILanguageHash equ 0x17727bf8
SetThreadpoolStackInformationHash equ 0x93bcf0ac
SetThreadpoolThreadMaximumHash equ 0x670a568e
SetThreadpoolThreadMinimumHash equ 0x7424307c
SetThreadpoolTimerHash equ 0xaecc751d
SetThreadpoolWaitHash equ 0xaace089d
SetTimeZoneInformationHash equ 0xe2184fb1
SetTimerQueueTimerHash equ 0xb1d57937
SetUnhandledExceptionFilterHash equ 0x31e9ba06
SetUserGeoIDHash equ 0x787058ff
SetVDMCurrentDirectoriesHash equ 0x6b8ce34f
SetVolumeLabelAHash equ 0xea073ce9
SetVolumeLabelWHash equ 0xea073cff
SetVolumeMountPointAHash equ 0x92b7428e
SetVolumeMountPointWHash equ 0x92b742a4
SetWaitableTimerHash equ 0x9eb37314
SetWaitableTimerExHash equ 0xbfa306e7
SetXStateFeaturesMaskHash equ 0x6a313244
SetupCommHash equ 0xd44af709
ShowConsoleCursorHash equ 0xaca05f70
SignalObjectAndWaitHash equ 0x313cf5c5
SizeofResourceHash equ 0x662bcde6
SleepHash equ 0x04c43eb7
SleepConditionVariableCSHash equ 0x6e1b1730
SleepConditionVariableSRWHash equ 0x55480b18
SleepExHash equ 0xe4af75ca
SortCloseHandleHash equ 0x1e0c39a2
SortGetHandleHash equ 0x3d2c5d00
StartThreadpoolIoHash equ 0x2808be4e
SubmitThreadpoolWorkHash equ 0xba85ffaf
SuspendThreadHash equ 0xfc7fad46
SwitchToFiberHash equ 0x5215b93d
SwitchToThreadHash equ 0x087e73d9
SystemTimeToFileTimeHash equ 0xa9a4ace0
SystemTimeToTzSpecificLocalTimeHash equ 0x8fecc709
SystemTimeToTzSpecificLocalTimeExHash equ 0x47d7319c
TerminateJobObjectHash equ 0x9e65641b
TerminateProcessHash equ 0xc78f7cee
TerminateThreadHash equ 0xd2e963ab
TermsrvAppInstallModeHash equ 0xdaf30bc8
Thread32FirstHash equ 0xb71a2227
Thread32NextHash equ 0xab14f09c
TlsAllocHash equ 0x2f07bb1a
TlsFreeHash equ 0x1a4cede7
TlsGetValueHash equ 0xfde8d9b6
TlsSetValueHash equ 0xdc76f42a
Toolhelp32ReadProcessMemoryHash equ 0x0830e822
TransactNamedPipeHash equ 0x1a392a9d
TransmitCommCharHash equ 0x341a1b72
TryAcquireSRWLockExclusiveHash equ 0xf2324b76
TryAcquireSRWLockSharedHash equ 0xe4990e8d
TryEnterCriticalSectionHash equ 0x273e6689
TrySubmitThreadpoolCallbackHash equ 0x1315c27e
TzSpecificLocalTimeToSystemTimeHash equ 0x66860857
TzSpecificLocalTimeToSystemTimeExHash equ 0xdd25576a
UTRegisterHash equ 0x9d8d8e62
UTUnRegisterHash equ 0x1587645b
UnhandledExceptionFilterHash equ 0xfc009bc4
UnlockFileHash equ 0x4391e300
UnlockFileExHash equ 0xa6a52bd3
UnmapViewOfFileHash equ 0x7f75f35b
UnregisterApplicationRecoveryCallbackHash equ 0xa77e666e
UnregisterApplicationRestartHash equ 0x50a6e41b
UnregisterConsoleIMEHash equ 0x84282c66
UnregisterWaitHash equ 0x1527e7f1
UnregisterWaitExHash equ 0x6acdb884
UpdateCalendarDayOfWeekHash equ 0x828dfda0
UpdateProcThreadAttributeHash equ 0x014b65d3
UpdateResourceAHash equ 0x963a2f0a
UpdateResourceWHash equ 0x963a2f20
VDMConsoleOperationHash equ 0x2496134f
VDMOperationStartedHash equ 0x42916299
VerLanguageNameAHash equ 0xe56917db
VerLanguageNameWHash equ 0xe56917f1
VerSetConditionMaskHash equ 0x00363308
VerifyConsoleIoHandleHash equ 0x26d8d38c
VerifyScriptsHash equ 0xabd0be2f
VerifyVersionInfoAHash equ 0xe6bd1694
VerifyVersionInfoWHash equ 0xe6bd16aa
VirtualAllocHash equ 0xe069970a
VirtualAllocExHash equ 0x6c60055d
VirtualAllocExNumaHash equ 0x88194898
VirtualFreeHash equ 0x2847d3f7
VirtualFreeExHash equ 0x35a2bb0a
VirtualLockHash equ 0x284a82b6
VirtualProtectHash equ 0x90472964
VirtualProtectExHash equ 0x9b226937
VirtualQueryHash equ 0xe14f0c9d
VirtualQueryExHash equ 0xc9be6230
VirtualUnlockHash equ 0x4f06660f
WTSGetActiveConsoleSessionIdHash equ 0x0dcb4c60
WaitCommEventHash equ 0xd881ecd9
WaitForDebugEventHash equ 0xf8e44e1b
WaitForMultipleObjectsHash equ 0xb48f0b50
WaitForMultipleObjectsExHash equ 0xccf98023
WaitForSingleObjectHash equ 0xd12beebb
WaitForSingleObjectExHash equ 0x35eb34ce
WaitForThreadpoolIoCallbacksHash equ 0xc22b2eae
WaitForThreadpoolTimerCallbacksHash equ 0x3af6f4e3
WaitForThreadpoolWaitCallbacksHash equ 0xad0191bf
WaitForThreadpoolWorkCallbacksHash equ 0xbe2deba3
WaitNamedPipeAHash equ 0x26c4340f
WaitNamedPipeWHash equ 0x26c43425
WakeAllConditionVariableHash equ 0xf35c24fa
WakeConditionVariableHash equ 0x0e5a5353
WerGetFlagsHash equ 0x7973c835
WerRegisterFileHash equ 0x80657023
WerRegisterMemoryBlockHash equ 0x30669b85
WerRegisterRuntimeExceptionModuleHash equ 0xc51da78a
WerSetFlagsHash equ 0x5801e2a9
WerUnregisterFileHash equ 0x811c983c
WerUnregisterMemoryBlockHash equ 0x97cfd54c
WerUnregisterRuntimeExceptionModuleHash equ 0x5afe5b63
WerpCleanupMessageMappingHash equ 0x1b5c5c3f
WerpInitiateRemoteRecoveryHash equ 0x95a48dc0
WerpNotifyLoadStringResourceHash equ 0xf20056ba
WerpNotifyLoadStringResourceExHash equ 0x7345990d
WerpNotifyUseStringResourceHash equ 0xc066e511
WerpStringLookupHash equ 0x0c9d2cb7
WideCharToMultiByteHash equ 0x0f4844fd
WinExecHash equ 0xb39a426d
Wow64DisableWow64FsRedirectionHash equ 0xff0e6f0d
Wow64EnableWow64FsRedirectionHash equ 0xc96d7682
Wow64GetThreadContextHash equ 0xf5f45e2c
Wow64GetThreadSelectorEntryHash equ 0x676cce90
Wow64RevertWow64FsRedirectionHash equ 0xa34d44a3
Wow64SetThreadContextHash equ 0x88cac4a0
Wow64SuspendThreadHash equ 0x73de48e9
WriteConsoleAHash equ 0x9fb762a9
WriteConsoleInputAHash equ 0x09e26c6f
WriteConsoleInputVDMAHash equ 0x44331dd4
WriteConsoleInputVDMWHash equ 0x44331dea
WriteConsoleInputWHash equ 0x09e26c85
WriteConsoleOutputAHash equ 0x7bf893a8
WriteConsoleOutputAttributeHash equ 0x6f7806e3
WriteConsoleOutputCharacterAHash equ 0xb196d6d1
WriteConsoleOutputCharacterWHash equ 0xb196d6e7
WriteConsoleOutputWHash equ 0x7bf893be
WriteConsoleWHash equ 0x9fb762bf
WriteFileHash equ 0x2398d9db
WriteFileExHash equ 0xa0c9d7ee
WriteFileGatherHash equ 0xf97c13b6
WritePrivateProfileSectionAHash equ 0x77173961
WritePrivateProfileSectionWHash equ 0x77173977
WritePrivateProfileStringAHash equ 0xf4f4464b
WritePrivateProfileStringWHash equ 0xf4f44661
WritePrivateProfileStructAHash equ 0xf4f99307
WritePrivateProfileStructWHash equ 0xf4f9931d
WriteProcessMemoryHash equ 0x85528ed1
WriteProfileSectionAHash equ 0x7a4a8d06
WriteProfileSectionWHash equ 0x7a4a8d1c
WriteProfileStringAHash equ 0x4fe56a06
WriteProfileStringWHash equ 0x4fe56a1c
WriteTapemarkHash equ 0xa3b777ce
ZombifyActCtxHash equ 0xc2c3ade7
_hreadHash equ 0xa80b48ff
_hwriteHash equ 0x59aa5596
_lcloseHash equ 0x5f613e2b
_lcreatHash equ 0x5f63d0bc
_llseekHash equ 0x5fe31917
_lopenHash equ 0xa84273b7
_lreadHash equ 0xa843a703
_lwriteHash equ 0x607db812
lstrcatHash equ 0x1bf64771
lstrcatAHash equ 0x62d2a6f0
lstrcatWHash equ 0x62d2a706
lstrcmpHash equ 0x1bf648e1
lstrcmpAHash equ 0x62d2d380
lstrcmpWHash equ 0x62d2d396
lstrcmpiHash equ 0x62d2d3a8
lstrcmpiAHash equ 0xf787a199
lstrcmpiWHash equ 0xf787a1af
lstrcpyHash equ 0x1bf64947
lstrcpyAHash equ 0x62d2dfda
lstrcpyWHash equ 0x62d2dff0
lstrcpynHash equ 0x62d2e007
lstrcpynAHash equ 0xf789211a
lstrcpynWHash equ 0xf7892130
lstrlenHash equ 0x1bf669b0
lstrlenAHash equ 0x62d6cc91
lstrlenWHash equ 0x62d6cca7
