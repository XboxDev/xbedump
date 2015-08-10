const char* xboxkrnlExports[] = {
    NULL,
    "AvGetSavedDataAddress",                    // @1
    "AvSendTVEncoderOption",                    // @2
    "AvSetDisplayMode",                         // @3
    "AvSetSavedDataAddress",                    // @4
    "DbgBreakPoint",                            // @5
    "DbgBreakPointWithStatus",                  // @6
    "DbgLoadImageSymbols",                      // @7
    "DbgPrint",                                 // @8
    "HalReadSMCTrayState",                      // @9
    "DbgPrompt",                                // @10
    "DbgUnLoadImageSymbols",                    // @11
    "ExAcquireReadWriteLockExclusive",          // @12
    "ExAcquireReadWriteLockShared",             // @13
    "ExAllocatePool",                           // @14
    "ExAllocatePoolWithTag",                    // @15
    "ExEventObjectType",                        // @16 (Object)
    "ExFreePool",                               // @17
    "ExInitializeReadWriteLock",                // @18
    "ExInterlockedAddLargeInteger",             // @19
    "ExInterlockedAddLargeStatistic",           // @20
    "ExInterlockedCompareExchange64",           // @21
    "ExMutantObjectType",                       // @22 (Object)
    "ExQueryPoolBlockSize",                     // @23
    "ExQueryNonVolatileSetting",                // @24
    "ExReadWriteRefurbInfo",                    // @25
    "ExRaiseException",                         // @26
    "ExRaiseStatus",                            // @27
    "ExReleaseReadWriteLock",                   // @28
    "ExSaveNonVolatileSetting",                 // @29
    "ExSemaphoreObjectType",                    // @30 (Object)
    "ExTimerObjectType",                        // @31 (Object)
    "ExfInterlockedInsertHeadList",             // @32
    "ExfInterlockedInsertTailList",             // @33
    "ExfInterlockedRemoveHeadList",             // @34
    "FscGetCacheSize",                          // @35
    "FscInvalidateIdleBlocks",                  // @36
    "FscSetCacheSize",                          // @37
    "HalClearSoftwareInterrupt",                // @38
    "HalDisableSystemInterrupt",                // @39
    "HalDiskCachePartitionCount",               // @40 (Object)
    "HalDiskModelNumber",                       // @41 (Object)
    "HalDiskSerialNumber",                      // @42 (Object)
    "HalEnableSystemInterrupt",                 // @43
    "HalGetInterruptVector",                    // @44
    "HalReadSMBusValue",                        // @45
    "HalReadWritePCISpace",                     // @46
    "HalRegisterShutdownNotification",          // @47
    "HalRequestSoftwareInterrupt",              // @48
    "HalReturnToFirmware",                      // @49
    "HalWriteSMBusValue",                       // @50
    "InterlockedCompareExchange",               // @51
    "InterlockedDecrement",                     // @52
    "InterlockedIncrement",                     // @53
    "InterlockedExchange",                      // @54
    "InterlockedExchangeAdd",                   // @55
    "InterlockedFlushSList",                    // @56
    "InterlockedPopEntrySList",                 // @57
    "InterlockedPushEntrySList",                // @58
    "IoAllocateIrp",                            // @59
    "IoBuildAsynchronousFsdRequest",            // @60
    "IoBuildDeviceIoControlRequest",            // @61
    "IoBuildSynchronousFsdRequest",             // @62
    "IoCheckShareAccess",                       // @63
    "IoCompletionObjectType",                   // @64 (Object)
    "IoCreateDevice",                           // @65
    "IoCreateFile",                             // @66
    "IoCreateSymbolicLink",                     // @67
    "IoDeleteDevice",                           // @68
    "IoDeleteSymbolicLink",                     // @69
    "IoDeviceObjectType",                       // @70 (Object)
    "IoFileObjectType",                         // @71 (Object)
    "IoFreeIrp",                                // @72
    "IoInitializeIrp",                          // @73
    "IoInvalidDeviceRequest",                   // @74
    "IoQueryFileInformation",                   // @75
    "IoQueryVolumeInformation",                 // @76
    "IoQueueThreadIrp",                         // @77
    "IoRemoveShareAccess",                      // @78
    "IoSetIoCompletion",                        // @79
    "IoSetShareAccess",                         // @80
    "IoStartNextPacket",                        // @81
    "IoStartNextPacketByKey",                   // @82
    "IoStartPacket",                            // @83
    "IoSynchronousDeviceIoControlRequest",      // @84
    "IoSynchronousFsdRequest",                  // @85
    "IofCallDriver",                            // @86
    "IofCompleteRequest",                       // @87
    "KdDebuggerEnabled",                        // @88 (Object)
    "KdDebuggerNotPresent",                     // @89 (Object)
    "IoDismountVolume",                         // @90
    "IoDismountVolumeByName",                   // @91
    "KeAlertResumeThread",                      // @92
    "KeAlertThread",                            // @93
    "KeBoostPriorityThread",                    // @94
    "KeBugCheck",                               // @95
    "KeBugCheckEx",                             // @96
    "KeCancelTimer",                            // @97
    "KeConnectInterrupt",                       // @98
    "KeDelayExecutionThread",                   // @99
    "KeDisconnectInterrupt",                    // @100
    "KeEnterCriticalRegion",                    // @101
    "MmGlobalData",                             // @102 (Object)
    "KeGetCurrentIrql",                         // @103
    "KeGetCurrentThread",                       // @104
    "KeInitializeApc",                          // @105
    "KeInitializeDeviceQueue",                  // @106
    "KeInitializeDpc",                          // @107
    "KeInitializeEvent",                        // @108
    "KeInitializeInterrupt",                    // @109
    "KeInitializeMutant",                       // @110
    "KeInitializeQueue",                        // @111
    "KeInitializeSemaphore",                    // @112
    "KeInitializeTimerEx",                      // @113
    "KeInsertByKeyDeviceQueue",                 // @114
    "KeInsertDeviceQueue",                      // @115
    "KeInsertHeadQueue",                        // @116
    "KeInsertQueue",                            // @117
    "KeInsertQueueApc",                         // @118
    "KeInsertQueueDpc",                         // @119
    "KeInterruptTime",                          // @120 (Object)
    "KeIsExecutingDpc",                         // @121
    "KeLeaveCriticalRegion",                    // @122
    "KePulseEvent",                             // @123
    "KeQueryBasePriorityThread",                // @124
    "KeQueryInterruptTime",                     // @125
    "KeQueryPerformanceCounter",                // @126
    "KeQueryPerformanceFrequency",              // @127
    "KeQuerySystemTime",                        // @128
    "KeRaiseIrqlToDpcLevel",                    // @129
    "KeRaiseIrqlToSynchLevel",                  // @130
    "KeReleaseMutant",                          // @131
    "KeReleaseSemaphore",                       // @132
    "KeRemoveByKeyDeviceQueue",                 // @133
    "KeRemoveDeviceQueue",                      // @134
    "KeRemoveEntryDeviceQueue",                 // @135
    "KeRemoveQueue",                            // @136
    "KeRemoveQueueDpc",                         // @137
    "KeResetEvent",                             // @138
    "KeRestoreFloatingPointState",              // @139
    "KeResumeThread",                           // @140
    "KeRundownQueue",                           // @141
    "KeSaveFloatingPointState",                 // @142
    "KeSetBasePriorityThread",                  // @143
    "KeSetDisableBoostThread",                  // @144
    "KeSetEvent",                               // @145
    "KeSetEventBoostPriority",                  // @146
    "KeSetPriorityProcess",                     // @147
    "KeSetPriorityThread",                      // @148
    "KeSetTimer",                               // @149
    "KeSetTimerEx",                             // @150
    "KeStallExecutionProcessor",                // @151
    "KeSuspendThread",                          // @152
    "KeSynchronizeExecution",                   // @153
    "KeSystemTime",                             // @154 (Object)
    "KeTestAlertThread",                        // @155
    "KeTickCount",                              // @156 (Object)
    "KeTimeIncrement",                          // @157 (Object)
    "KeWaitForMultipleObjects",                 // @158
    "KeWaitForSingleObject",                    // @159
    "KfRaiseIrql",                              // @160
    "KfLowerIrql",                              // @161
    "KiBugCheckData",                           // @162 (Object)
    "KiUnlockDispatcherDatabase",               // @163
    "LaunchDataPage",                           // @164 (Object)
    "MmAllocateContiguousMemory",               // @165
    "MmAllocateContiguousMemoryEx",             // @166
    "MmAllocateSystemMemory",                   // @167
    "MmClaimGpuInstanceMemory",                 // @168
    "MmCreateKernelStack",                      // @169
    "MmDeleteKernelStack",                      // @170
    "MmFreeContiguousMemory",                   // @171
    "MmFreeSystemMemory",                       // @172
    "MmGetPhysicalAddress",                     // @173
    "MmIsAddressValid",                         // @174
    "MmLockUnlockBufferPages",                  // @175
    "MmLockUnlockPhysicalPage",                 // @176
    "MmMapIoSpace",                             // @177
    "MmPersistContiguousMemory",                // @178
    "MmQueryAddressProtect",                    // @179
    "MmQueryAllocationSize",                    // @180
    "MmQueryStatistics",                        // @181
    "MmSetAddressProtect",                      // @182
    "MmUnmapIoSpace",                           // @183
    "NtAllocateVirtualMemory",                  // @184
    "NtCancelTimer",                            // @185
    "NtClearEvent",                             // @186
    "NtClose",                                  // @187
    "NtCreateDirectoryObject",                  // @188
    "NtCreateEvent",                            // @189
    "NtCreateFile",                             // @190
    "NtCreateIoCompletion",                     // @191
    "NtCreateMutant",                           // @192
    "NtCreateSemaphore",                        // @193
    "NtCreateTimer",                            // @194
    "NtDeleteFile",                             // @195
    "NtDeviceIoControlFile",                    // @196
    "NtDuplicateObject",                        // @197
    "NtFlushBuffersFile",                       // @198
    "NtFreeVirtualMemory",                      // @199
    "NtFsControlFile",                          // @200
    "NtOpenDirectoryObject",                    // @201
    "NtOpenFile",                               // @202
    "NtOpenSymbolicLinkObject",                 // @203
    "NtProtectVirtualMemory",                   // @204
    "NtPulseEvent",                             // @205
    "NtQueueApcThread",                         // @206
    "NtQueryDirectoryFile",                     // @207
    "NtQueryDirectoryObject",                   // @208
    "NtQueryEvent",                             // @209
    "NtQueryFullAttributesFile",                // @210
    "NtQueryInformationFile",                   // @211
    "NtQueryIoCompletion",                      // @212
    "NtQueryMutant",                            // @213
    "NtQuerySemaphore",                         // @214
    "NtQuerySymbolicLinkObject",                // @215
    "NtQueryTimer",                             // @216
    "NtQueryVirtualMemory",                     // @217
    "NtQueryVolumeInformationFile",             // @218
    "NtReadFile",                               // @219
    "NtReadFileScatter",                        // @220
    "NtReleaseMutant",                          // @221
    "NtReleaseSemaphore",                       // @222
    "NtRemoveIoCompletion",                     // @223
    "NtResumeThread",                           // @224
    "NtSetEvent",                               // @225
    "NtSetInformationFile",                     // @226
    "NtSetIoCompletion",                        // @227
    "NtSetSystemTime",                          // @228
    "NtSetTimerEx",                             // @229
    "NtSignalAndWaitForSingleObjectEx",         // @230
    "NtSuspendThread",                          // @231
    "NtUserIoApcDispatcher",                    // @232
    "NtWaitForSingleObject",                    // @233
    "NtWaitForSingleObjectEx",                  // @234
    "NtWaitForMultipleObjectsEx",               // @235
    "NtWriteFile",                              // @236
    "NtWriteFileGather",                        // @237
    "NtYieldExecution",                         // @238
    "ObCreateObject",                           // @239
    "ObDirectoryObjectType",                    // @240 (Object)
    "ObInsertObject",                           // @241
    "ObMakeTemporaryObject",                    // @242
    "ObOpenObjectByName",                       // @243
    "ObOpenObjectByPointer",                    // @244
    "ObpObjectHandleTable",                     // @245 (Object)
    "ObReferenceObjectByHandle",                // @246
    "ObReferenceObjectByName",                  // @247
    "ObReferenceObjectByPointer",               // @248
    "ObSymbolicLinkObjectType",                 // @249 (Object)
    "ObfDereferenceObject",                     // @250
    "ObfReferenceObject",                       // @251
    "PhyGetLinkState",                          // @252
    "PhyInitialize",                            // @253
    "PsCreateSystemThread",                     // @254
    "PsCreateSystemThreadEx",                   // @255
    "PsQueryStatistics",                        // @256
    "PsSetCreateThreadNotifyRoutine",           // @257
    "PsTerminateSystemThread",                  // @258
    "PsThreadObjectType",                       // @259 (Object)
    "RtlAnsiStringToUnicodeString",             // @260
    "RtlAppendStringToString",                  // @261
    "RtlAppendUnicodeStringToString",           // @262
    "RtlAppendUnicodeToString",                 // @263
    "RtlAssert",                                // @264
    "RtlCaptureContext",                        // @265
    "RtlCaptureStackBackTrace",                 // @266
    "RtlCharToInteger",                         // @267
    "RtlCompareMemory",                         // @268
    "RtlCompareMemoryUlong",                    // @269
    "RtlCompareString",                         // @270
    "RtlCompareUnicodeString",                  // @271
    "RtlCopyString",                            // @272
    "RtlCopyUnicodeString",                     // @273
    "RtlCreateUnicodeString",                   // @274
    "RtlDowncaseUnicodeChar",                   // @275
    "RtlDowncaseUnicodeString",                 // @276
    "RtlEnterCriticalSection",                  // @277
    "RtlEnterCriticalSectionAndRegion",         // @278
    "RtlEqualString",                           // @279
    "RtlEqualUnicodeString",                    // @280
    "RtlExtendedIntegerMultiply",               // @281
    "RtlExtendedLargeIntegerDivide",            // @282
    "RtlExtendedMagicDivide",                   // @283
    "RtlFillMemory",                            // @284
    "RtlFillMemoryUlong",                       // @285
    "RtlFreeAnsiString",                        // @286
    "RtlFreeUnicodeString",                     // @287
    "RtlGetCallersAddress",                     // @288
    "RtlInitAnsiString",                        // @289
    "RtlInitUnicodeString",                     // @290
    "RtlInitializeCriticalSection",             // @291
    "RtlIntegerToChar",                         // @292
    "RtlIntegerToUnicodeString",                // @293
    "RtlLeaveCriticalSection",                  // @294
    "RtlLeaveCriticalSectionAndRegion",         // @295
    "RtlLowerChar",                             // @296
    "RtlMapGenericMask",                        // @297
    "RtlMoveMemory",                            // @298
    "RtlMultiByteToUnicodeN",                   // @299
    "RtlMultiByteToUnicodeSize",                // @300
    "RtlNtStatusToDosError",                    // @301
    "RtlRaiseException",                        // @302
    "RtlRaiseStatus",                           // @303
    "RtlTimeFieldsToTime",                      // @304
    "RtlTimeToTimeFields",                      // @305
    "RtlTryEnterCriticalSection",               // @306
    "RtlUlongByteSwap",                         // @307
    "RtlUnicodeStringToAnsiString",             // @308
    "RtlUnicodeStringToInteger",                // @309
    "RtlUnicodeToMultiByteN",                   // @310
    "RtlUnicodeToMultiByteSize",                // @311
    "RtlUnwind",                                // @312
    "RtlUpcaseUnicodeChar",                     // @313
    "RtlUpcaseUnicodeString",                   // @314
    "RtlUpcaseUnicodeToMultiByteN",             // @315
    "RtlUpperChar",                             // @316
    "RtlUpperString",                           // @317
    "RtlUshortByteSwap",                        // @318
    "RtlWalkFrameChain",                        // @319
    "RtlZeroMemory",                            // @320
    "XboxEEPROMKey",                            // @321 (Object)
    "XboxHardwareInfo",                         // @322 (Object)
    "XboxHDKey",                                // @323 (Object)
    "XboxKrnlVersion",                          // @324 (Object)
    "XboxSignatureKey",                         // @325 (Object)
    "XeImageFileName",                          // @326 (Object)
    "XeLoadSection",                            // @327
    "XeUnloadSection",                          // @328
    "READ_PORT_BUFFER_UCHAR",                   // @329
    "READ_PORT_BUFFER_USHORT",                  // @330
    "READ_PORT_BUFFER_ULONG",                   // @331
    "WRITE_PORT_BUFFER_UCHAR",                  // @332
    "WRITE_PORT_BUFFER_USHORT",                 // @333
    "WRITE_PORT_BUFFER_ULONG",                  // @334
    "XcSHAInit",                                // @335
    "XcSHAUpdate",                              // @336
    "XcSHAFinal",                               // @337
    "XcRC4Key",                                 // @338
    "XcRC4Crypt",                               // @339
    "XcHMAC",                                   // @340
    "XcPKEncPublic",                            // @341
    "XcPKDecPrivate",                           // @342
    "XcPKGetKeyLen",                            // @343
    "XcVerifyPKCS1Signature",                   // @344
    "XcModExp",                                 // @345
    "XcDESKeyParity",                           // @346
    "XcKeyTable",                               // @347
    "XcBlockCrypt",                             // @348
    "XcBlockCryptCBC",                          // @349
    "XcCryptService",                           // @350
    "XcUpdateCrypto",                           // @351
    "RtlRip",                                   // @352
    "XboxLANKey",                               // @353 (Object)
    "XboxAlternateSignatureKeys",               // @354 (Object)
    "XePublicKeyData",                          // @355 (Object)
    "HalBootSMCVideoMode",                      // @356 (Object)
    "IdexChannelObject",                        // @357 (Object)
    "HalIsResetOrShutdownPending",              // @358
    "IoMarkIrpMustComplete",                    // @359
    "HalInitiateShutdown",                      // @360
    "RtlSnprintf",                              // @361
    "RtlSprintf",                               // @362
    "RtlVsnprintf",                             // @363
    "RtlVsprintf",                              // @364
    "HalEnableSecureTrayEject",                 // @365
    "HalWriteSMCScratchRegister",               // @366
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "MmDbgAllocateMemory",                      // @374
    "MmDbgFreeMemory",                          // @375
    "MmDbgQueryAvailablePages",                 // @376
    "MmDbgReleaseAddress",                      // @377
    "MmDbgWriteCheck",                          // @378
};
