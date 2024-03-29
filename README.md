# SceKernelModulemgr-Reverse

Target FW version: 3.60.

There is nothing to guarantee perfect operation.

## Module flags

How to get this value: `((SceModuleInfoInternal *)info_addr)->flags` or with a DevKit `psp2ctrl pobjects SceWebKitProcess > SceWebKitProcess_pobjects.txt`

```
0x8000 : relocatable
0x4000 : process main module
0x2000 : has syscall export
0x1000 : system module
0x0800 : unknown
0x0400 : shared text module (if has dipsw 0xD2)
0x0200 : shared host
0x0100 : shared text module (if not has dipsw 0xD2)
0x0002 : unknown
0x0001 : module location is in cdialog?
```

### Other notes

> module entry call stack

If the process is a game program and the module has flag 0x1000 set, then an entry is called with stack size 0x4000, otherwise the stack size is 0x40000.

## Module load flags

### Allowed flag
```
kernel : 0x7D9F0.
user   : 0xF0.
```

Flags that are not in the allowed flag can be resolved by calling an internal function.

```
0x1     : Load as shared module
0x4     : Load as process main module
0x10    : Bypass inhibit state 0x20 and load to cdialog
0x20    : Use devkit memory (maybe)
0x100   : Load as bootfs module
0x800   : Load from image module
0x1000  : Load as proc path module(app0: etc)
0x8000  : Bypass inhibit state 0x10(system module)
0x20000 : Do not call some sysroot functions
0x40000 : Do not call some sysroot functions
```

## Inhibit state flags
```
0x1    : Inhibit shared
0x2    : Inhibit to disable ASLR
0x10   : Inhibit load module level 1
0x20   : Inhibit load module level 2
0x30   : Inhibit load module level 3 (cannot bypass by module load flags)
0x8000 : Inhibit to "inhibit to disable ASLR"
```

## Todo list

* [ ] Module load (30% done)
* [ ] Module start
* [ ] Module stop
* [ ] Module unload (30% done)
* [ ] Get module info/list RE (80% done. These can be easily done because the structure reverse is almost completed.)
* [ ] ELF relocation for Module load
* [ ] structure RE

## Tested functions

```
sceKernelGetModuleIdByAddrForKernel
sceKernelGetModuleInfoForKernel
sceKernelGetModuleListForKernel
sceKernelGetModulePathForKernel
sceKernelGetModuleFingerprintForKernel
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
0x99890202 : sceKernelGetModuleIsSharedByAddrForKernel
0x97CF7B4E : sceKernelGetModuleListForKernel
0x779A1025 : sceKernelGetModulePathForKernel
0xEEA92F1F : sceKernelGetModuleNIDForKernel
0x1BDE2ED2 : sceKernelGetModuleNonlinkedImportInfoForKernel
0x20A27FA9 : sceKernelGetProcessMainModuleForKernel
0x2A69385E : sceKernelModuleUnloadMySelfForKernel
0x01360661 : sceKernelMountBootfsForKernel
0x9C838A6B : sceKernelUmountBootfsForKernel
0x0E33258E : sceKernelUnloadProcessModulesForKernel
0x432DCC7A : sceKernelStartPreloadingModulesForKernel
0x3382952B : sceKernelSetupForModulemgrForKernel
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
sceKernelGetAllowedSdkVersionOnSystem
sceKernelGetModuleIdByAddr
sceKernelGetModuleInfo
sceKernelGetModuleList
sceKernelGetLibraryInfoByNID
sceKernelGetSystemSwVersion
sceKernelInhibitLoadingModule
sceKernelIsCalledFromSysModule
```

## List of only frame (prototype) reversed

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

SceModulemgrForKernel_952535A3 : (sceKernelGetModuleImportNonlinkedInfoByNIDForKernel)
SceModulemgrForKernel_8D1AA624 : (sceKernelGetModuleKernelExportListForKernel)
SceModulemgrForKernel_F95D09C2 : (sceKernelGetModuleAppInfoForKernel, temp name)
SceModulemgrForKernel_FF2264BB : (sceKernelGetModuleNonlinkedListForKernel)

SceModulemgrForKernel_60E176C8 : (sceKernelRegisterDebugCBForKernel, temp name)
SceModulemgrForKernel_9D20C9BB : (sceKernelUnregisterDebugCBForKernel, temp name)
SceModulemgrForKernel_B73BE671 : maybe sceKernelGetModuleLibStubInfoForKernel
SceModulemgrForKernel_FB251B7A : maybe sceKernelGetModuleLibImportListForKernel

SceModulemgrForKernel_29CB2771 : Related to import/export
SceModulemgrForKernel_4865C72C : Related to non-linked?
SceModulemgrForKernel_F3CD647F : set two param
```

### SceModulemgrForDriver

```
sceKernelLoadModuleForDriver
sceKernelStartModuleForDriver
sceKernelLoadStartModuleForDriver
sceKernelLoadStartModuleForPidForDriver
sceKernelUnloadModuleForDriver
sceKernelStopModuleForDriver
sceKernelStopUnloadModuleForDriver
sceKernelStopUnloadModuleForPidForDriver
sceKernelLoadStartSharedModuleForPidForDriver
SceModulemgrForDriver_02D3D0C1(ksceKernelStopUnloadSharedModuleForPid)
SceModulemgrForDriver_0975B104(ksceKernelReleaseLibary)
SceModulemgrForDriver_861638AD(ksceKernelRegisterLibary)
```

### SceModulemgr

```
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

