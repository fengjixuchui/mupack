
#pragma once
#include "../stdafx.h"
using namespace pe_bliss;


typedef void(_stdcall *tmentry)(LPVOID, LPVOID);
typedef void(_stdcall *trestore)(LPVOID, LPVOID);
typedef void(_stdcall *ttlscallback)(PVOID, DWORD, DWORD);



#pragma pack(push, 1)

typedef struct compdata
{
	LPVOID src;
	DWORD clen;
	DWORD nlen;
	DWORD ulen;
	DWORD iscode;
};

typedef PVOID(WINAPI* tVirtualAlloc)(PVOID, DWORD, DWORD, DWORD);
typedef PVOID(WINAPI* tRtlMoveMemory)(PVOID, PVOID, DWORD);
typedef BOOL(WINAPI* tVirtualFree)(PVOID, DWORD, DWORD);
typedef BOOL(WINAPI* tVirtualProtect)(PVOID, DWORD, DWORD, PDWORD);


typedef struct stubcode
{
	DWORD mentry;
	DWORD restore;
	DWORD codefilter;
	DWORD depacker;
	DWORD OriginalImports;
	DWORD OriginalImportsSize;
	DWORD OriginalResources;
	DWORD OriginalResourcesSize;
	DWORD OriginalRelocations;
	DWORD OriginalRelocationsSize;
	DWORD OriginalLoadConfig;
	DWORD code_locsz;
    DWORD code_loc;
	DWORD tls_callbackold;
	DWORD TlsCallbackNew;
	DWORD IsDepacked;
	DWORD ImageBase;
	DWORD numsections;
	DWORD packed_ptr;
	DWORD sizepacked;
	DWORD sizeunpacked;
	DWORD tls_index;
	DWORD lock_opcode;
	//IAT
	DWORD loadlib;
	DWORD getproc;
	DWORD virtualalloc;
	DWORD virtualfree;
	DWORD virtualprotect;
	DWORD rtlmovemem;
	DWORD iatend;
};
extern struct stubcode stubcode_ptr;
#pragma pack(pop)

void rebuild_resources(pe_base *image, resource_directory *new_root_dir);
unsigned char* build_stub(int OEP, int imagebase, int section_va, int * stubsize);
unsigned char* prepare_stub(int* stubsize);
unsigned int get_bootloadersz();
int stubcode_sz();

int compress_file(TCHAR* filename);
