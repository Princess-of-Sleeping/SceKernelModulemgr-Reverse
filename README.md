# SceKernelModulemgr-Reverse
target version : 3.60<br>
There is nothing to guarantee perfect operation<br>

## Tested functions
```
sceKernelGetModuleIdByAddrForKernel
sceKernelGetModuleInfoForKernel
sceKernelGetModuleListForKernel
sceKernelGetModulePathForKernel
sceKernelGetModuleNIDForKernel
sceKernelGetModuleNonlinkedImportInfoForKernel
sceKernelGetProcessMainModuleForKernel

sceKernelGetModuleInfoByAddrForDriver
sceKernelSearchModuleByNameForDriver

sceKernelGetLibraryInfoByNID
```

## Partially working function
```
sceKernelLoadModuleForKernel
sceKernelUnloadModuleForKernel
sceKernelLoadModuleForPidForKernel
sceKernelUnloadModuleForPidForKernel
```

## Reverse Completed
### SceModulemgrForKernel
```
0xFDD7F646 : sceKernelFinalizeKblForKernel
0x66606301 : sceKernelGetModuleEntryPointForKernel
0x78DBC027 : sceKernelGetModuleEntryPointForUserForKernel
0x0053BA4A : sceKernelGetModuleIdByAddrForKernel
0xD269F915 : sceKernelGetModuleInfoForKernel
0x8309E043 : sceKernelGetModuleInfoMinByAddrForKernel
0x7A1E882D : sceKernelGetModuleInhibitStateForKernel
0xFE303863 : sceKernelGetModuleInternalForKernel
0x2C2618D9 : sceKernelGetModuleInternalByAddrForKernel
0x97CF7B4E : sceKernelGetModuleListForKernel
0x779A1025 : sceKernelGetModulePathForKernel
0xEEA92F1F : sceKernelGetModuleNIDForKernel
0x1BDE2ED2 : sceKernelGetModuleNonlinkedImportInfoForKernel
0x20A27FA9 : sceKernelGetProcessMainModuleForKernel
0x2A69385E : sceKernelModuleUnloadMySelfForKernel
0x01360661 : sceKernelMountBootfsForKernel
0x9C838A6B : sceKernelUmountBootfsForKernel
0xB427025E : sceKernelRegisterSyscallForKernel
```

### SceModulemgrForDriver
```
0x5182E212 : sceKernelGetSystemSwVersionForDriver
0xBBE1771C : sceKernelSearchModuleByNameForDriver
0x1D9E0F7E : sceKernelGetModuleInfoByAddrForDriver
```

### SceModulemgr
```
sceKernelGetModuleIdByAddr
sceKernelGetModuleInfo
sceKernelGetLibraryInfoByNID
sceKernelGetSystemSwVersion
sceKernelInhibitLoadingModule
```

## List of only frame(prototype) reversed
### SceModulemgrForKernel
```
0xFA21D8CB : sceKernelLoadModuleForPidForKernel
0x6DF745D5 : sceKernelStartModuleForPidForKernel
0x7BB4CE54 : sceKernelStopModuleForPidForKernel
0x5972E2CC : sceKernelUnloadModuleForPidForKernel

0x6A655255 : sceKernelGetModuleLibraryInfoForKernel

0xD4BF409C : sceKernelGetModuleLibExportListForKernel
0x3B93CF88 : sceKernelGetModuleListByImportForKernel (old name is sceKernelGetModuleUidForKernel)

0x1D341231 : sceKernelGetProcessLibStubIdListForKernel (old name is sceKernelGetModuleLibStubIdListForKernel)
0x1FDEAE16 : sceKernelGetProcessLibraryIdListForKernel (old name is sceKernelGetModuleUidListForKernel, sceKernelGetModuleExportLibraryListForKernel)

0x2DD3B511 : sceKernelGetModuleImportListForKernel (old name is sceKernelGetModuleImportListForKernel)
0x619925F1 : sceKernelGetModuleExportListForKernel (old name is sceKernelGetModuleLibraryIdListForKernel)

0x410E1D2E : sceKernelGetModuleList2ForKernel

0x448810D5 : sceKernelLoadPtLoadSegForFwloaderForKernel

0xAC4EABDB : sceKernelLoadProcessImageForKernel
0x3AD26B43 : sceKernelLoadPreloadingModulesForKernel
0x432DCC7A : sceKernelStartPreloadingModulesForKernel
0x0E33258E : sceKernelUnloadProcessModulesForKernel

0x3382952B : sceKernelSetupForModulemgrForKernel

SceModulemgrForKernel_952535A3 : (sceKernelGetModuleImportNonlinkedInfoByNIDForKernel)
SceModulemgrForKernel_99890202 : (sceKernelGetModuleIsSharedByAddrForKernel)
SceModulemgrForKernel_8D1AA624 : (sceKernelGetModuleKernelExportListForKernel)
SceModulemgrForKernel_F95D09C2 : (sceKernelGetModuleAppInfoForKernel, temp name)
SceModulemgrForKernel_FF2264BB : (sceKernelGetModuleNonlinkedListForKernel)

SceModulemgrForKernel_29CB2771
SceModulemgrForKernel_4865C72C
SceModulemgrForKernel_60E176C8 : (sceKernelRegisterDebugCBForKernel, temp name)
SceModulemgrForKernel_9D20C9BB : (sceKernelRegisterDebugCBCheckForKernel, temp name)
SceModulemgrForKernel_B73BE671
SceModulemgrForKernel_F3CD647F
SceModulemgrForKernel_FB251B7A
```

### SceModulemgrForDriver
```
ksceKernelLoadModule
ksceKernelStartModule
ksceKernelLoadStartModule
ksceKernelLoadStartModuleForPid
ksceKernelUnloadModule
ksceKernelStopModule
ksceKernelStopUnloadModule
ksceKernelStopUnloadModuleForPid
ksceKernelLoadStartSharedModuleForPid
SceModulemgrForDriver_02D3D0C1(ksceKernelStopUnloadSharedModuleForPid)
SceModulemgrForDriver_0975B104(ksceKernelReleaseLibary)
SceModulemgrForDriver_861638AD(ksceKernelRegisterLibary)
```

### SceModulemgr
```
sceKernelGetAllowedSdkVersionOnSystem
sceKernelGetModuleList
sceKernelIsCalledFromSysModule
_sceKernelOpenModule
_sceKernelCloseModule
_sceKernelLoadModule
_sceKernelStartModule
_sceKernelLoadStartModule
_sceKernelStopModule
_sceKernelUnloadModule
_sceKernelStopUnloadModule
```

## yet not Reversed List

### SceModulemgrForDriver
maybe n/a

### SceModulemgrForKernel
n/a

### SceModulemgr
n/a

