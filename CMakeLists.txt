cmake_minimum_required(VERSION 2.8)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

project(SceKernelModulemgrReverse)
include("${VITASDK}/share/vita.cmake" REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -Wall -O3 -fno-inline")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fno-exceptions")

enable_language(C ASM)

add_executable(SceKernelModulemgrReverse
  src/main.c
  src/module_utility.c
  src/modulemgr.c
  src/modulemgr_for_driver.c
  src/modulemgr_for_kernel.c
  src/module_debug.c
  src/module_search.c
  src/module_syscall.c
  src/module_user.c
  src/module_inhibit_loading.c
  src/libkernel.c
)

target_link_libraries(SceKernelModulemgrReverse
  SceDebugForDriver_stub
  SceDipswForDriver_stub
  SceIofilemgrForDriver_stub
  SceThreadmgrForDriver_stub
  SceSysmemForDriver_stub
  SceSysclibForDriver_stub
  SceSysrootForDriver_stub
  SceSysrootForKernel_stub
  SceKernelUtilsForDriver_stub
  SceCpuForDriver_stub
  SceCpuForKernel_stub
  SceQafMgrForDriver_stub
  taihenForKernel_stub

  ${CMAKE_CURRENT_BINARY_DIR}/../extra/libSceSysmem_stub.a
  ${CMAKE_CURRENT_BINARY_DIR}/../extra/libSceKernelIntrMgr_stub.a
  ${CMAKE_CURRENT_BINARY_DIR}/../extra/libSceProcessmgr_stub.a
  ${CMAKE_CURRENT_BINARY_DIR}/../extra/libSceKernelThreadMgr_stub.a
)

set_target_properties(SceKernelModulemgrReverse
  PROPERTIES LINK_FLAGS "-nostdlib"
)

vita_create_self(modulemgr_rev.skprx SceKernelModulemgrReverse
  CONFIG exports.yml
  UNSAFE
)
