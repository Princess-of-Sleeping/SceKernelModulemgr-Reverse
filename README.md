# SceKernelModulemgr-Reverse
target version : 3.60<br>
There is nothing to guarantee perfect operation<br>

## Tested functions
sceKernelGetModuleIdByAddrForKernel<br>
sceKernelGetModuleInfoForKernel<br>
sceKernelGetModulePathForKernel<br>
sceKernelGetModuleNIDForKernel<br>
sceKernelGetProcessMainModuleForKernel<br>
sceKernelModuleGetNonlinkedImportInfoForKernel<br>

sceKernelGetModuleInfoByAddrForDriver<br>
sceKernelSearchModuleByNameForDriver<br>

## Partially working function
sceKernelLoadModuleForKernel<br>
sceKernelUnloadModuleForKernel<br>
sceKernelLoadModuleForPidForKernel<br>
sceKernelUnloadModuleForPidForKernel<br>

## Reverse Completed
### SceModulemgrForKernel
0xFDD7F646 : sceKernelFinalizeKblForKernel<br>
0x0053BA4A : sceKernelGetModuleIdByAddrForKernel<br>
0xD269F915 : sceKernelGetModuleInfoForKernel<br>
0x8309E043 : sceKernelGetModuleInfoMinByAddrForKernel<br>
0x7A1E882D : sceKernelGetModuleInhibitStateForKernel<br>
0xFE303863 : sceKernelGetModuleInternalForKernel<br>
0x779A1025 : sceKernelGetModulePathForKernel<br>
0xEEA92F1F : sceKernelGetModuleNIDForKernel<br>
0x20A27FA9 : sceKernelGetProcessMainModuleForKernel<br>
0x2A69385E : sceKernelModuleUnloadMySelfForKernel<br>
0x01360661 : sceKernelMountBootfsForKernel<br>
0x9C838A6B : sceKernelUmountBootfsForKernel<br>
0xB427025E : sceKernelRegisterSyscallForKernel<br>
0x1BDE2ED2 : sceKernelModuleGetNonlinkedImportInfoForKernel<br>
SceModulemgrForKernel_2C2618D9<br>
SceModulemgrForKernel_66606301<br>
SceModulemgrForKernel_78DBC027<br>

### SceModulemgrForDriver
0x5182E212 : sceKernelGetSystemSwVersionForDriver<br>
0xBBE1771C : sceKernelSearchModuleByNameForDriver<br>
0x1D9E0F7E : sceKernelGetModuleInfoByAddrForDriver<br>

### SceModulemgr
sceKernelInhibitLoadingModule<br>
sceKernelGetModuleInfo<br>
sceKernelGetSystemSwVersion<br>
sceKernelGetModuleIdByAddr<br>

## List of only frame(prototype) reversed
### SceModulemgrForKernel
0xFA21D8CB : sceKernelLoadModuleForPidForKernel<br>
0x6DF745D5 : sceKernelStartModuleForPidForKernel<br>
0x7BB4CE54 : sceKernelStopModuleForPidForKernel<br>
0x5972E2CC : sceKernelUnloadModuleForPidForKernel<br>

0x6A655255 : sceKernelGetModuleInfo2ForKernel<br>

0xD4BF409C : sceKernelGetModuleLibraryInfoForKernel<br>
0x3B93CF88 : sceKernelGetModuleUidForKernel<br>
0x1FDEAE16 : sceKernelGetModuleUidListForKernel<br>
0x97CF7B4E : sceKernelGetModuleListForKernel<br>
0x410E1D2E : sceKernelGetModuleList2ForKernel<br>

0x448810D5 : sceKernelLoadPtLoadSegForFwloaderForKernel<br>

0xAC4EABDB : sceKernelLoadProcessImageForKernel<br>
0x3AD26B43 : sceKernelLoadPreloadingModulesForKernel<br>
0x432DCC7A : sceKernelStartPreloadingModulesForKernel<br>
0x0E33258E : sceKernelUnloadProcessModulesForKernel<br>

0x3382952B : sceKernelSetupForModulemgrForKernel<br>

SceModulemgrForKernel_1D341231<br>
SceModulemgrForKernel_29CB2771<br>
SceModulemgrForKernel_2C2618D9<br>
SceModulemgrForKernel_2DD3B511<br>
SceModulemgrForKernel_4865C72C<br>
SceModulemgrForKernel_60E176C8<br>
SceModulemgrForKernel_619925F1<br>
SceModulemgrForKernel_8D1AA624<br>
SceModulemgrForKernel_952535A3<br>
SceModulemgrForKernel_99890202<br>
SceModulemgrForKernel_9D20C9BB<br>
SceModulemgrForKernel_B73BE671<br>
SceModulemgrForKernel_F3CD647F<br>
SceModulemgrForKernel_F95D09C2<br>
SceModulemgrForKernel_FB251B7A<br>
SceModulemgrForKernel_FF2264BB<br>

### SceModulemgrForDriver
ksceKernelLoadModule<br>
ksceKernelStartModule<br>
ksceKernelLoadStartModule<br>
ksceKernelLoadStartModuleForPid<br>
ksceKernelUnloadModule<br>
ksceKernelStopModule<br>
ksceKernelStopUnloadModule<br>
ksceKernelStopUnloadModuleForPid<br>
ksceKernelLoadStartSharedModuleForPid<br>
SceModulemgrForDriver_02D3D0C1(ksceKernelStopUnloadSharedModuleForPid)<br>
SceModulemgrForDriver_0975B104(ksceKernelReleaseLibary)<br>
SceModulemgrForDriver_861638AD(ksceKernelRegisterLibary)<br>

### SceModulemgr
sceKernelGetAllowedSdkVersionOnSystem<br>
sceKernelGetLibraryInfoByNID<br>
sceKernelGetModuleList<br>
sceKernelIsCalledFromSysModule<br>
_sceKernelOpenModule<br>
_sceKernelCloseModule<br>
_sceKernelLoadModule<br>
_sceKernelStartModule<br>
_sceKernelLoadStartModule<br>
_sceKernelStopModule<br>
_sceKernelUnloadModule<br>
_sceKernelStopUnloadModule<br>

## yet not Reversed List

### SceModulemgrForDriver
maybe n/a<br>

### SceModulemgrForKernel
n/a<br>

### SceModulemgr
n/a<br>

