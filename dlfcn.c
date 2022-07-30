/*
Copyright (c) 2022 Szilard Biro

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <exec/execbase.h>
#include <dos/dostags.h>
#include <proto/dos.h>
#include <proto/exec.h>
#include <exec/memory.h>
#include <dos/doshunks.h>

#include "dlfcn.h"

#define FINDPROCESS_TRIES (3)

static BOOL errorClear = TRUE;
static char *errorString;
static struct MinList sobjs = {(struct MinNode *)&sobjs.mlh_Tail, NULL, (struct MinNode *)&sobjs.mlh_Head};

typedef struct
{
	struct MinNode node;
	void *address;
	char name[1]; // variable length
} soexport_t;

typedef struct
{
	struct MinNode node;
	struct MinList exports;
	struct Process *proc;
	//char name[1]; // variable length
} soinstance_t;

static void SOSetError(char *str)
{
	errorString = str;
	errorClear = FALSE;
}

static soexport_t *SOAddExport(soinstance_t *instance, void *address, /*const*/ char *name, LONG namelen)
{
	soexport_t *export;

	if (*name != '_')
		return NULL; // not a C function
	name++;
	namelen--;
	//Printf("%s address %lx name '%s' namelen %ld\n", __FUNCTION__, address, name, namelen);

	export = AllocVec(sizeof(soexport_t) + namelen + 1, MEMF_CLEAR);
	if (!export)
		return NULL;
	export->address = address;
	CopyMem(name, export->name, namelen);
	export->name[namelen] = '\0';
	AddTail((struct List *)&instance->exports, (struct Node *)export);

	return export;
}

static void SORemoveExports(soinstance_t *instance)
{
	soexport_t *export;
	while ((export = (soexport_t *)RemHead((struct List *)&instance->exports)))
	{
		FreeVec(export);
	}
}

static void *SOResolveSymbol(soinstance_t *instance, const char *name)
{
	soexport_t *export;
	for (export = (soexport_t *)instance->exports.mlh_TailPred; export->node.mln_Pred; export = (soexport_t *)export->node.mln_Pred)
	{
		char *s1, *s2;
		for (s1 = (char *)name, s2 = export->name; *s1 && *s1 == *s2; s1++, s2++);
		if (*s1 == '\0')
			return export->address;
	}
	return NULL;
}

// loosely based on HunkFunc by Dirk Stoecker and HunkFunk by Olaf Barthel
static LONG SOParseHunks(BPTR fh, soinstance_t *instance, ULONG *seglist)
{
	ULONG Type = 0, Data, i;
	LONG From, To;
	UWORD DataW;
	void *segstart = NULL;
	char name[257];

	FRead(fh, &Type, 1, 4);
	if (Type != HUNK_HEADER)
	{
		// invalid hunk header
		return 1;
	}

	// resident libraries
	do
	{
		ULONG data2;

		if (FRead(fh, &Data, 1, 4) != 4)
			return 2;

		if (!Data)
			break;

		if ((data2 = Data) > 64)
			data2 = 64;
		Data -= data2;

		if (Seek(fh, 4 * data2, OFFSET_CURRENT) != 4 * data2)
			return 2;

		if (Data && Seek(fh, 4 * Data, OFFSET_CURRENT) < 0)
			return 2;
	} while(TRUE);

	FRead(fh, &Data, 1, 4);
	FRead(fh, &From, 1, 4);
	FRead(fh, &To, 1, 4);

	// header memflags
	if ((Data & 0xE0000000) || (From & 0xFFFF0000) || (To & 0xFFFF0000))
	{
		if ((Data & HUNKF_CHIP) && (Data & HUNKF_FAST))
		{
			// extended type
			Seek(fh, 4, OFFSET_CURRENT);
		}
	}

	// hunk lengths/types
	for (i = 0; i < To - From + 1; ++i)
	{
		FRead(fh, &Data, 1, 4);

		if ((Data & HUNKF_CHIP) && (Data & HUNKF_FAST))
		{
			// extended type
			Seek(fh, 4, OFFSET_CURRENT);
		}
	}

	// process the hunks
	while (TRUE)
	{
		if (FRead(fh, &Type, 1, 4) != 4)
		{
			// extra bytes at end of file
			return 0;
		}

		switch (Type & 0xFFFF)
		{
		case HUNK_NAME:
		case HUNK_DEBUG:
			FRead(fh, &Data, 1, 4);
			Seek(fh, 4 * Data, OFFSET_CURRENT);
			break;

		case HUNK_CODE:
			FRead(fh, &Data, 1, 4);
			Data <<= 2;
			Data &= 0x7FFFFFFF;
			Seek(fh, Data, OFFSET_CURRENT);
			break;

		case HUNK_DATA:
			FRead(fh, &Data, 1, 4);
			Data <<= 2;
			Data &= 0x7FFFFFFF;
			Seek(fh, Data, OFFSET_CURRENT);
			break;

		case HUNK_BSS:
			Seek(fh, 4, OFFSET_CURRENT);
			break;

		case HUNK_RELRELOC32:
		case HUNK_ABSRELOC16:
		case HUNK_RELOC32:
			do
			{
				if (FRead(fh, &Data, 1, 4) != 4)
					return 2;
				if (!Data)
					break;

				Seek(fh, 4, OFFSET_CURRENT);
				if (Seek(fh, 4 * (Data&0xFFFF), OFFSET_CURRENT) < 0)
					return 3;
			} while(TRUE);
			break;

		case HUNK_RELOC32SHORT:
		case HUNK_DREL32:
			do
			{
				if (FRead(fh, &DataW, 1, 2) != 2)
					return 2;
				if (!DataW)
					break;

				Seek(fh, 2 * (1 + DataW), OFFSET_CURRENT);
			} while(TRUE);
			// longword alignment
			i = Seek(fh, 0, OFFSET_CURRENT);
			if (i & 2)
				Seek(fh, 2, OFFSET_CURRENT);
			break;

		case HUNK_SYMBOL:
			if (!seglist)
			{
				// we ran out of seglists
				return 5;
			}
			segstart = seglist+1;
			seglist = BADDR(*seglist);
			//Printf("%s new symbol hunk, seglist %lx segstart %lx\n", __FUNCTION__, seglist, segstart,);

			do
			{
				FRead(fh, &Data, 1, 4);

				if (!Data)
					break;

				i = (Data & 0xFFFFFF) * 4;
				FRead(fh, name, 1, i);
				name[i] = 0;
				FRead(fh, &Data, 1, 4);
				//Printf("%s offset %lu name %s\n", __FUNCTION__, Data, name);

				if (!SOAddExport(instance, (char *)segstart + Data, name, i))
				{
					// out of memory
					return 4;
				}
			} while(TRUE);
			break;

		case HUNK_END:
		case HUNK_BREAK:
			break;

		default:
			// unknown hunk type
			return 1;
		}
	}

	return 0;
}

static soinstance_t *SOAddInstance(BPTR fh, struct Process *proc)
{
	soinstance_t *instance;
	struct CommandLineInterface *cli = BADDR(proc->pr_CLI);
	ULONG *seglist = BADDR(cli->cli_Module);

	instance = AllocVec(sizeof(soinstance_t), MEMF_CLEAR);
	if (!instance)
	{
		SOSetError("can't allocate the instance memory");
		return NULL;
	}
	if (SOParseHunks(fh, instance, seglist))
	{
		FreeVec(instance);
		SOSetError("can't parse the hunks");
		return NULL;
	}
	instance->proc = proc;
	AddTail((struct List *)&sobjs, (struct Node *)instance);

	return instance;
}

static void SORemoveInstance(soinstance_t *instance)
{
	SORemoveExports(instance);
	Remove((struct Node *)instance);
	FreeVec(instance);
}

/*
static void SORemoveInstances(void)
{
	soinstance_t *instance;
	while ((instance = (soinstance_t *)RemHead((struct List *)&sobjs)))
	{
		SORemoveInstance(instance);
	}
}
*/

static STRPTR NameFromFHAlloc(BPTR fh)
{
	LONG error = 0;
	LONG size;
	STRPTR fullname = NULL;

	for (size = 256; fullname == NULL && error == 0; size += 256)
	{
		fullname = AllocVec(size, MEMF_ANY);
		if (fullname)
		{
			if (!NameFromFH(fh, fullname, size))
			{
				error = IoErr();
				if (error == ERROR_LINE_TOO_LONG)
				{
					error = 0;
					FreeVec(fullname);
					fullname = NULL;
				}
			}
		}
		else
		{
			error = -1;
		}
	}

	return fullname;
}

static struct Process *FindWaitingProcess(STRPTR name)
{
	struct Node *node;
	struct Process *proc;

	//Printf("%s(%s)\n", __FUNCTION__, name);
	proc = NULL;
	Forbid();
	for (node = SysBase->TaskWait.lh_Head; node->ln_Succ; node = node->ln_Succ)
	{
		struct Process *pr;
		struct CommandLineInterface *cli;
		char *command;
		char *s1, *s2;

		if (node->ln_Type != NT_PROCESS)
			continue;
		pr = (struct Process *)node;
		cli = BADDR(pr->pr_CLI);
		if (!cli)
			continue;

		command = BADDR(cli->cli_CommandName);
		s1 = (char *)name;
		s2 = command + 1;
		for ( ; *s1 && *s1 == *s2; s1++, s2++);
		if (*s1 == '\0')
		{
			proc = pr;
			break;
		}
	}
	Permit();

	return proc;
}

static BOOL IsProcessRunning(struct Process *proc)
{
	BOOL running;
	struct Node *node;

	//Printf("%s(%lx)\n", __FUNCTION__, proc);

	running = FALSE;

	Forbid();

	for (node = SysBase->TaskWait.lh_Head; node->ln_Succ; node = node->ln_Succ)
	{
		if (proc == (struct Process *)node)
		{
			running = TRUE;
			break;
		}
	}

	if (!running)
	{
		for (node = SysBase->TaskReady.lh_Head; node->ln_Succ; node = node->ln_Succ)
		{
			if (proc == (struct Process *)node)
			{
				running = TRUE;
				break;
			}
		}
	}

	Permit();

	return running;
}

void *dlopen(const char *filename, int flag)
{
	BPTR fh;
	STRPTR fullname;
	void *handle;
	int retries;
	struct Process *proc;
	//BPTR input, output;

	//Printf("%s(%s,%ld)\n", __FUNCTION__, filename, flag);

	handle = NULL;
	if ((fh = Open((STRPTR)filename, MODE_OLDFILE)))
	{
		//Printf("%s fh %ld\n", __FUNCTION__, fh);
		if ((fullname = NameFromFHAlloc(fh)))
		{
			struct TagItem tags[] =
			{
				{SYS_Asynch, TRUE},
				{SYS_Input, 0},
				{SYS_Output, 0},
				{TAG_DONE}
			};
			//Printf("%s fullname %s\n", __FUNCTION__, fullname);
			if (!SystemTagList(fullname, tags))
			{
				retries = 0;
				do
				{
					if ((proc = FindWaitingProcess(fullname)))
						break;
					Delay(10);
				} while (retries++ < FINDPROCESS_TRIES);
				if (proc)
				{
					/*
					struct CommandLineInterface *cli = BADDR(proc->pr_CLI);
					Printf("%s proc %lx '%s' command '%b'\n", __FUNCTION__, proc, proc->pr_Task.tc_Node.ln_Name, cli->cli_CommandName);
					*/
					handle = SOAddInstance(fh, proc);
				}
				else
				{
					SOSetError("can't find the CLI process");
				}
			}
			else
			{
				SOSetError("can't start the CLI process");
			}
			FreeVec(fullname);
		}
		else
		{
			SOSetError("can't determine the canonical path");
		}
		Close(fh);
	}
	else
	{
		SOSetError("can't open the file");
	}

	return handle;
}

char *dlerror(void)
{
	if (errorClear)
		return NULL;
	errorClear = TRUE;
	return errorString;
}

int dlclose(void *handle)
{
	int retries = 0;
	soinstance_t *instance = handle;
	struct Process *proc;

	if (!instance)
	{
		SOSetError("NULL handle passed to dlclose");
		return -1;
	}

	proc = instance->proc;
	if (!IsProcessRunning(proc))
	{
		SOSetError("the process is no longer running");
		return -1;
	}

	do
	{
		/*
		struct CommandLineInterface *cli = BADDR(proc->pr_CLI);
		Printf("%s signaling proc %lx '%s' command '%b'\n", __FUNCTION__, proc, proc->pr_Task.tc_Node.ln_Name, cli->cli_CommandName);
		*/
		Signal((struct Task *)proc, SIGBREAKF_CTRL_C);
		if (!IsProcessRunning(proc))
			break;
		Delay(10);
	} while (!IsProcessRunning(proc) && retries++ < FINDPROCESS_TRIES);
	if (retries >= FINDPROCESS_TRIES)
	{
		SOSetError("the process didn't respond to the CTRL-C signal");
		return -1;
	}
	SORemoveInstance(instance);

	return 0;
}

void *dlsym(void *handle, const char *symbol)
{
	void *sym = NULL;
	soinstance_t *instance = handle;
	if (instance)
	{
		sym = SOResolveSymbol(instance, symbol);
	}
	return sym;
}
