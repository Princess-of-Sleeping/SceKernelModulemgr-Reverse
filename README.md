# SceKernelModulemgr-Reverse
There is nothing to guarantee perfect operation<br>

## Tested functions
sceKernelGetModuleIdByAddrForKernel<br>

ksceKernelGetModuleInfo<br>
ksceKernelSearchModuleByName<br>
SceModulemgrForDriver_1D9E0F7E(ksceKernelGetModuleInfoByAddr)<br>

## Reverse Completed
### SceModulemgrForKernel
sceKernelFinalizeKblForKernel<br>
sceKernelGetModuleIdByAddrForKernel<br>
sceKernelGetModuleInfoForKernel<br>
sceKernelGetModuleInfoMinByAddrForKernel<br>
sceKernelGetModuleInternalForKernel<br>
sceKernelGetProcessMainModulePathForKernel<br>
sceKernelModuleUnloadMySelfForKernel<br>
sceKernelMountBootfsForKernel<br>
sceKernelUmountBootfsForKernel<br>
sceKernelRegisterSyscallForKernel<br>
SceModulemgrForKernel_2C2618D9<br>
SceModulemgrForKernel_66606301<br>
SceModulemgrForKernel_78DBC027<br>
SceModulemgrForKernel_EEA92F1F(sceKernelModuleGetProcessMainModuleXXXXXForKernel)<br>

### SceModulemgrForDriver
ksceKernelGetSystemSwVersion<br>
ksceKernelSearchModuleByName<br>
SceModulemgrForDriver_1D9E0F7E(ksceKernelGetModuleInfoByAddr)<br>

### SceModulemgr
sceKernelInhibitLoadingModule<br>
sceKernelGetModuleInfo<br>
sceKernelGetSystemSwVersion<br>
sceKernelGetModuleIdByAddr<br>

## List of only frame(prototype) reversed
### SceModulemgrForKernel

sceKernelLoadModuleForPidForKernel<br>
sceKernelStartModuleForPidForKernel<br>
sceKernelStopModuleForPidForKernel<br>
sceKernelUnloadModuleForPidForKernel<br>

sceKernelGetModuleInfo2ForKernel<br>

sceKernelGetModuleLibraryInfoForKernel<br>
sceKernelGetModuleUidForKernel<br>
sceKernelGetModuleUidListForKernel<br>
sceKernelGetModuleListForKernel<br>
sceKernelGetModuleList2ForKernel<br>

sceKernelGetProcessMainModuleForKernel<br>

sceKernelLoadPtLoadSegForFwloaderForKernel<br>

sceKernelLoadProcessImageForKernel<br>
sceKernelLoadPreloadingModulesForKernel<br>
sceKernelStartPreloadingModulesForKernel<br>
sceKernelStopUnloadProcessModulesForKernel<br>

sceKernelSetupForModulemgrForKernel<br>

SceModulemgrForKernel_1BDE2ED2<br>
SceModulemgrForKernel_1D341231<br>
SceModulemgrForKernel_29CB2771<br>
SceModulemgrForKernel_2C2618D9<br>
SceModulemgrForKernel_2DD3B511<br>
SceModulemgrForKernel_4865C72C<br>
SceModulemgrForKernel_60E176C8<br>
SceModulemgrForKernel_619925F1<br>
SceModulemgrForKernel_66606301<br>
SceModulemgrForKernel_78DBC027<br>
SceModulemgrForKernel_7A1E882D<br>
SceModulemgrForKernel_8D1AA624<br>
SceModulemgrForKernel_952535A3<br>
SceModulemgrForKernel_99890202<br>
SceModulemgrForKernel_9D20C9BB<br>
SceModulemgrForKernel_B73BE671<br>
SceModulemgrForKernel_EEA92F1F<br>
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

