#include <stdio.h>
#include <dlfcn.h>

int main(int argc, char *argv[])
{
	void *handle;
	int *exportedVar1;
	int *exportedVar2;
	int (*exportedFunc)(int val);
	int val;

	handle = dlopen("testlib.so", 0);
	if (!handle)
	{
		printf("dlopen error: %s\n", dlerror());
		return 1;
	}

	exportedVar1 = dlsym(handle, "exportedVar1");
	if (exportedVar1)
	{
		val = *exportedVar1;
		printf("exportedVar1 %p (%d)\n", (void *)exportedVar1, val);
	}
	else
		printf("exportedVar1 not found!\n");

	exportedVar2 = dlsym(handle, "exportedVar2");
	if (exportedVar2)
		printf("exportedVar2 %p (%x)\n", (void *)exportedVar2, *exportedVar2);
	else
		printf("exportedVar2 not found!\n");

	exportedFunc = dlsym(handle, "exportedFunc");
	if (exportedFunc)
	{
		printf("exportedFunc %p\n", exportedFunc);
		val = exportedFunc(0xFEEDFACE);
		printf("exportedFunc returned: %x\n", val);
	}
	else
	{
		printf("exportedFunc not found!\n");
	}

	if (dlclose(handle))
	{
		printf("dlclose error: %s\n", dlerror());
		return 1;
	}

	return 0;
}
