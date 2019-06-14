
void func_0x810014a8(void);
void func_0x810014D4(void);
int func_0x81001ec4(SceUID pid);
void *func_0x81001f0c(SceUID modid);

int func_0x810021b8(SceUID pid);
int func_0x810021c0(SceUID pid);
int func_0x810021d8(SceUID pid);

int func_0x81003708(uint16_t flag);

void *func_0x8100498c(SceUID pid, int len);
int func_0x810049fc(const char *path);
int func_0x81004a54(void);

int func_0x81005648(SceUID pid, int flags, void *dst);
int func_0x81005a70(void *r0, const char *path, int flags);
void func_0x81005b04(void *r0); // print module load info

int func_0x81006CF4(int a1, int a2, int a3, void *a4);
module_tree_top_t *func_0x81006e60(SceUID pid, int *cpu_suspend_intr);
int func_0x81006e90(module_tree_top_t *module_tree_top, int cpu_suspend_intr);

int func_0x81007148(const char *path);
int func_0x810071a8(void *r0);
int func_0x81007790(SceUID pid, SceUID modid, SceKernelModuleInfo_fix_t *info);
int func_0x81007A84(void *a1, const void *a2, void *a3); // yet not Reversed
int func_0x81007BBC(SceUID pid, const void *lr);
int func_0x81007C10(SceUID pid, const void *lr);
SceUID func_0x81007c5c(SceUID pid, const char *module_name);


