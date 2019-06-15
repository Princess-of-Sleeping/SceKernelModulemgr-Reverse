# SceKernelModulemgr-Reverse
There is nothing to guarantee perfect operation<br>

## Reverse Completed
### SceModulemgrForKernel
ksceKernelGetModuleInfo<br>
ksceKernelGetModuleInternal<br>
ksceKernelMountBootfs<br>
ksceKernelUmountBootfs<br>
SceModulemgrForKernel_66606301<br>
SceModulemgrForKernel_78DBC027<br>
SceModulemgrForKernel_B427025E(ksceKernelRegisterSyscall)<br>

### SceModulemgrForDriver
ksceKernelGetSystemSwVersion<br>
ksceKernelSearchModuleByName<br>

### SceModulemgr
sceKernelInhibitLoadingModule<br>

## List of only frame(prototype) reversed
### SceModulemgrForKernel
ksceKernelLoadModuleForPid<br>
ksceKernelStartModuleForPid<br>
ksceKernelUnloadModuleForPid<br>
ksceKernelStopModuleForPid<br>
SceModulemgrForKernel_0053BA4A<br>
SceModulemgrForKernel_2A69385E<br>
SceModulemgrForKernel_3AD26B43(sceKernelLoadPreloadingModulesForKernel)<br>
SceModulemgrForKernel_432DCC7A(maybe sceKernelStartPreloadingModulesForKernel)<br>
SceModulemgrForKernel_F95D09C2<br>
SceModulemgrForKernel_FDD7F646(sceKernelFinalizeKblForKernel)<br>

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
SceModulemgrForDriver_861638AD<br>

## yet not Reversed List

### SceModulemgrForDriver
SceModulemgrForDriver_0975B104<br>
SceModulemgrForDriver_1D9E0F7E<br>
more...?<br>

### SceModulemgrForKernel
SceModulemgrForKernel_0053BA4A<br>
SceModulemgrForKernel_0E33258E<br>
SceModulemgrForKernel_1BDE2ED2<br>
SceModulemgrForKernel_1D341231<br>
SceModulemgrForKernel_1FDEAE16<br>
SceModulemgrForKernel_20A27FA9<br>
SceModulemgrForKernel_29CB2771<br>
SceModulemgrForKernel_2C2618D9<br>
SceModulemgrForKernel_2DD3B511<br>
SceModulemgrForKernel_3382952B<br>
SceModulemgrForKernel_3B93CF88<br>
SceModulemgrForKernel_410E1D2E<br>
SceModulemgrForKernel_4865C72C<br>
SceModulemgrForKernel_60E176C8<br>
SceModulemgrForKernel_619925F1<br>
SceModulemgrForKernel_6A655255<br>
SceModulemgrForKernel_779A1025<br>
SceModulemgrForKernel_7A1E882D<br>
SceModulemgrForKernel_8309E043<br>
SceModulemgrForKernel_8D1AA624<br>
SceModulemgrForKernel_952535A3<br>
SceModulemgrForKernel_99890202<br>
SceModulemgrForKernel_9D20C9BB<br>
SceModulemgrForKernel_AC4EABDB<br>
SceModulemgrForKernel_B427025E<br>
SceModulemgrForKernel_B73BE671<br>
SceModulemgrForKernel_D4BF409C<br>
SceModulemgrForKernel_EEA92F1F<br>
SceModulemgrForKernel_F3CD647F<br>
SceModulemgrForKernel_FB251B7A<br>
SceModulemgrForKernel_FF2264BB<br>
maybe more...<br>

### SceModulemgr
sceKernelGetModuleList<br>
sceKernelGetModuleInfo<br>
sceKernelGetAllowedSdkVersionOnSystem<br>
sceKernelGetSystemSwVersion<br>
sceKernelIsCalledFromSysModule<br>
sceKernelGetLibraryInfoByNID<br>
sceKernelGetModuleIdByAddr<br>
SceModulemgr_086867A8<br>
SceModulemgr_60647592<br>
SceModulemgr_72CD301F<br>
SceModulemgr_849E78BE<br>
SceModulemgr_86EAEA0A<br>
SceModulemgr_8E4A7716<br>
SceModulemgr_9D674F45<br>
SceModulemgr_B4C5EF9E<br>

