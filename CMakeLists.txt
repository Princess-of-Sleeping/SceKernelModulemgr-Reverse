cmake_minimum_required(VERSION 2.8)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

project(SceKernelModulemgr_Reverse)
include("${VITASDK}/share/vita.cmake" REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -Wall -O3 -nostdlib")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fno-exceptions")

add_executable(SceKernelModulemgr_Reverse
  src/main.c
  src/modulemgr.c
  src/modulemgr_for_driver.c
  src/modulemgr_for_kernel.c
)

target_link_libraries(SceKernelModulemgr_Reverse
  SceDebugForDriver_stub
  SceIofilemgrForDriver_stub
  SceThreadmgrForDriver_stub
  SceSysmemForDriver_stub
  SceSysclibForDriver_stub
  SceSysrootForKernel_stub
  SceCpuForDriver_stub
  SceCpuForKernel_stub

  taihenForKernel_stub
  taihenModuleUtils_stub
)

vita_create_self(ModulemgrRev.skprx SceKernelModulemgr_Reverse
  CONFIG exports.yml
  UNSAFE
)
