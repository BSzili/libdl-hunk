#include <proto/dos.h>
#include <stdio.h>

// bss
int exportedVar1;

// data
int exportedVar2 = 0xDEADBEEF;

// code
int exportedFunc(int val)
{
	printf("testlib exported function, argument: %x\n", val);
	//printf("exportedVar1 %p exportedVar2 %p exportedFunc %p\n", &exportedVar1, &exportedVar2, &exportedFunc);
	return 0xABADCAFE;
}
