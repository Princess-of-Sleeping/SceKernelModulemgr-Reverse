# SceKernelModulemgr-Reverse
There is nothing to guarantee perfect operation<br>

## Tested functions
SceModulemgrForKernel_0053BA4A(ksceKernelGetModuleIdByAddr)<br>

ksceKernelGetModuleInfo<br>
ksceKernelSearchModuleByName<br>
SceModulemgrForDriver_1D9E0F7E(ksceKernelGetModuleInfoByAddr)<br>

## Reverse Completed
### SceModulemgrForKernel
ksceKernelGetModuleInfo<br>
ksceKernelGetModuleInternal<br>
ksceKernelGetProcessMainModulePath<br>
ksceKernelMountBootfs<br>
ksceKernelUmountBootfs<br>
SceModulemgrForKernel_0053BA4A(ksceKernelGetModuleIdByAddr)<br>
SceModulemgrForKernel_2A69385E(maybe ksceKernelModuleUnloadMySelf)<br>
SceModulemgrForKernel_2C2618D9<br>
SceModulemgrForKernel_66606301<br>
SceModulemgrForKernel_78DBC027<br>
SceModulemgrForKernel_B427025E(ksceKernelRegisterSyscall)<br>
SceModulemgrForKernel_EEA92F1F(ksceKernelModuleGetProcessMainModuleXXXXX)<br>

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
ksceKernelLoadModuleForPid<br>
ksceKernelStartModuleForPid<br>
ksceKernelUnloadModuleForPid<br>
ksceKernelStopModuleForPid<br>
SceModulemgrForKernel_0E33258E<br>
SceModulemgrForKernel_3AD26B43(sceKernelLoadPreloadingModulesForKernel)<br>
SceModulemgrForKernel_432DCC7A(maybe sceKernelStartPreloadingModulesForKernel)<br>
SceModulemgrForKernel_448810D5(sceKernelDecryptSelfByPathForKernel)<br>
SceModulemgrForKernel_AC4EABDB<br>
SceModulemgrForKernel_F95D09C2<br>
SceModulemgrForKernel_FDD7F646(sceKernelFinalizeKblForKernel)<br>
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
sceKernelIsCalledFromSysModule<br>
sceKernelGetLibraryInfoByNID<br>
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
SceModulemgrForKernel_1BDE2ED2<br>
SceModulemgrForKernel_1D341231<br>
SceModulemgrForKernel_1FDEAE16<br>
ksceKernelGetProcessMainModule<br>
SceModulemgrForKernel_29CB2771<br>
SceModulemgrForKernel_2DD3B511<br>
SceModulemgrForKernel_3382952B<br>
ksceKernelGetModuleUid<br>
ksceKernelGetModuleList2<br>
SceModulemgrForKernel_4865C72C<br>
SceModulemgrForKernel_60E176C8<br>
SceModulemgrForKernel_619925F1<br>
ksceKernelGetModuleInfo2<br>
SceModulemgrForKernel_7A1E882D<br>
SceModulemgrForKernel_8309E043<br>
SceModulemgrForKernel_8D1AA624<br>
SceModulemgrForKernel_952535A3<br>
SceModulemgrForKernel_99890202<br>
SceModulemgrForKernel_9D20C9BB<br>
SceModulemgrForKernel_B73BE671<br>
ksceKernelGetModuleLibraryInfo<br>
SceModulemgrForKernel_F3CD647F<br>
SceModulemgrForKernel_FB251B7A<br>
maybe more...<br>

### SceModulemgr
sceKernelGetModuleList<br>

