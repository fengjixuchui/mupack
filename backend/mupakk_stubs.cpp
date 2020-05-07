#include "../logger.h"
#include "../stdafx.h"
#include "powapack.h"
#include "xbyak/xbyak.h"
using namespace pe_bliss;
using namespace Xbyak;
using namespace Xbyak::util;

#define MARK_END_OF_FUNCTION(funcname)                                         \
  static void funcname##_eof_marker() {}
#define SIZEOF_FUNCTION(funcname)                                              \
  ((unsigned long)&funcname##_eof_marker - (unsigned long)&funcname)

extern "C" {
/*
static void restore(stubcode *p, INT_PTR base_offset)
{

        IMAGE_IMPORT_DESCRIPTOR *Imports;
        IMAGE_IMPORT_BY_NAME *iNames;
        DWORD dwThunk;
        DWORD *Thunk;
        DWORD *Function;
        Imports = (IMAGE_IMPORT_DESCRIPTOR*)(p->ImageBase + p->OriginalImports);


        while (Imports->Name)
        {
                HINSTANCE Lib = (*p->GetModuleHandleA)((const
char*)(Imports->Name + p->ImageBase)); dwThunk = Imports->OriginalFirstThunk ?
Imports->OriginalFirstThunk : Imports->FirstThunk; Thunk = (DWORD*)(dwThunk +
p->ImageBase); dwThunk = Imports->FirstThunk; while (*Thunk)
                {
                        iNames = (IMAGE_IMPORT_BY_NAME*)(*Thunk + p->ImageBase);
                        if (*Thunk & IMAGE_ORDINAL_FLAG)
                        {
                                Function = (DWORD*)(p->ImageBase + dwThunk);
                                *Function = (DWORD)((*p->GetProcAddress)(Lib,
(char*)LOWORD(*Thunk)));
                        }
                        else
                        {
                                Function = (DWORD*)(p->ImageBase + dwThunk);
                                *Function = (DWORD)((*p->GetProcAddress)(Lib,
(char*)iNames->Name));
                        }
                        dwThunk += sizeof(DWORD);
                        Thunk++;

                }

                Imports++;
        }
        if (p->OriginalRelocationsSize)
        {
                DWORD prelocs = p->ImageBase + p->OriginalRelocations;
                DWORD prelocs_end = prelocs + p->OriginalRelocationsSize;
                while (prelocs < prelocs_end)
                {
                        PIMAGE_BASE_RELOCATION preloc =
(PIMAGE_BASE_RELOCATION)prelocs; DWORD dwPageAddr = p->ImageBase +
preloc->VirtualAddress; DWORD dwBlockSize = preloc->SizeOfBlock; for (DWORD i =
4; i < (dwBlockSize >> 1); i++)
                        {
                                DWORD dwOffset = *(WORD*)(prelocs + (i << 1));
                                DWORD dwType = (dwOffset >> 12) & 0xf;
                                DWORD dwRPtr = dwPageAddr + (dwOffset & 0xfff);
                                if (dwType == IMAGE_REL_BASED_HIGHLOW)
                                {
                                        DWORD dwRDat = *(DWORD*)dwRPtr;
                                        dwRDat = dwRDat + base_offset;
                                        *(DWORD*)dwRPtr = dwRDat;
                                }
                        }
                        prelocs += dwBlockSize;
                }
        }
}

MARK_END_OF_FUNCTION(restore)


static void mentry_fr(stubcode *p, INT_PTR base_offset)
{
        if (p->IsDepacked == 0x01)return;

        HMODULE
        DWORD OldP = NULL;
        DWORD * fixup = (DWORD*)&p->VirtualAlloc;
        DWORD * fixup_end = (DWORD*)&p->OriginalImports;
        while (fixup < fixup_end) *fixup++ += base_offset;
        compdata *cmpdata = (compdata*)((DWORD)p->ocompdata + sizeof(DWORD));

        DWORD nlendiff = (DWORD)cmpdata->nlen - (DWORD)cmpdata->ulen;
        unsigned char* input_data = (unsigned char*)(p->ImageBase +
(DWORD)cmpdata->src + (DWORD)cmpdata->ulen); unsigned char* ucompd = (unsigned
char*)(*p->VirtualAlloc)(NULL, cmpdata->nlen, MEM_COMMIT, PAGE_READWRITE);
        (*p->VirtualProtect)((LPVOID)(p->ImageBase + (DWORD)cmpdata->src),
(DWORD)cmpdata->nlen, PAGE_EXECUTE_READWRITE, &OldP); typedef int(_stdcall
*tdecomp) (PVOID, PVOID); tdecomp decomp = (tdecomp)p->decomp; decomp(ucompd,
input_data); if (cmpdata->iscode)
        {
                tdefilt defilter = (tdefilt)p->codefilt;
                defilter(ucompd, cmpdata->nlen);
        }
        for (int i = 0; i < nlendiff; i++) input_data[i] = ucompd[i];
        (*p->VirtualFree)(ucompd, 0, MEM_RELEASE);
        cmpdata->ulen = OldP;

        p->restore(p, (LPVOID)base_offset);

        cmpdata = (compdata*)((DWORD)p->ocompdata + sizeof(DWORD));

        while (cmpdata->src)
        {
                if (cmpdata->clen)(*p->VirtualProtect)((LPVOID)(p->ImageBase +
(DWORD)cmpdata->src), (DWORD)cmpdata->nlen, (DWORD)cmpdata->ulen, &OldP);
                cmpdata++;
        }

        if (p->TlsCallbackBackup)
        {
                p->TlsCallbackBackup += p->ImageBase;
                p->TlsCallbackNew += p->ImageBase;
                PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK
*)p->TlsCallbackBackup; PIMAGE_TLS_CALLBACK* callback_bckup =
(PIMAGE_TLS_CALLBACK *)p->TlsCallbackNew; if (callback) { while (*callback) {
                                (*callback)((LPVOID)p->ImageBase,
DLL_PROCESS_ATTACH, NULL); *callback_bckup = *callback; callback_bckup++;
                                callback++;
                        }
                }
        }
        p->IsDepacked = 0x01;
}
MARK_END_OF_FUNCTION(mentry_fr)
*/

static  void _stdcall restore(stubcode *p, INT_PTR base_offset) {
  typedef FARPROC(WINAPI * tGetProcAddress)(HINSTANCE, LPCSTR);
  typedef HINSTANCE(WINAPI * tLoadLibraryA)(LPCSTR);
  tGetProcAddress getproc = (tGetProcAddress)p->getproc;
  tLoadLibraryA loadlib = (tLoadLibraryA)p->loadlib;
  IMAGE_IMPORT_BY_NAME *iNames;
  DWORD dwThunk;
  DWORD *Thunk;
  DWORD *Function;
  IMAGE_IMPORT_DESCRIPTOR *Imports =
      (IMAGE_IMPORT_DESCRIPTOR *)(p->ImageBase + p->OriginalImports);
  while (Imports->Name) {
    HMODULE Lib = loadlib((const char *)(Imports->Name + p->ImageBase));

    dwThunk = Imports->OriginalFirstThunk ? Imports->OriginalFirstThunk
                                          : Imports->FirstThunk;
    Thunk = (DWORD *)(dwThunk + p->ImageBase);
    dwThunk = Imports->FirstThunk;
    while (*Thunk) {
      iNames = (IMAGE_IMPORT_BY_NAME *)(*Thunk + p->ImageBase);
      if (*Thunk & IMAGE_ORDINAL_FLAG) {
        Function = (DWORD *)(p->ImageBase + dwThunk);
        *Function = (DWORD)(getproc(Lib, (char *)LOWORD(*Thunk)));
      } else {
        Function = (DWORD *)(p->ImageBase + dwThunk);
        *Function = (DWORD)(getproc(Lib, (char *)iNames->Name));
      }
      dwThunk += sizeof(DWORD);
      Thunk++;
    }
    Imports++;
  }

  if (p->OriginalRelocationsSize) {
      DWORD prelocs = p->ImageBase + p->OriginalRelocations;
      DWORD prelocs_end = prelocs + p->OriginalRelocationsSize;
      while (prelocs < prelocs_end) {
          PIMAGE_BASE_RELOCATION preloc = (PIMAGE_BASE_RELOCATION)prelocs;
          DWORD dwPageAddr = p->ImageBase + preloc->VirtualAddress;
          DWORD dwBlockSize = preloc->SizeOfBlock;
          for (DWORD i = 4; i < (dwBlockSize >> 1); i++) {
              DWORD dwOffset = *(WORD*)(prelocs + (i << 1));
              DWORD dwType = (dwOffset >> 12) & 0xf;
              DWORD dwRPtr = dwPageAddr + (dwOffset & 0xfff);
              if (dwType == IMAGE_REL_BASED_HIGHLOW) {
                  DWORD dwRDat = *(DWORD*)dwRPtr;
                  dwRDat = dwRDat + base_offset;
                  *(DWORD*)dwRPtr = dwRDat;
              }
          }
          prelocs += dwBlockSize;
      }
  }

  /*
  if(p->tls_oldindexrva)
      *(DWORD*)(p->tls_oldindexrva + p->ImageBase) = p->tls_index;
  if (p->TlsCallbackNew) {
      int offset = 0;
    PIMAGE_TLS_CALLBACK *callback = (PIMAGE_TLS_CALLBACK *)p->tls_callbackold + p->ImageBase;
      while (*callback) {
          PIMAGE_TLS_CALLBACK* callback_tmp = callback;
        (*callback_tmp)((LPVOID)p->ImageBase, DLL_PROCESS_ATTACH, NULL);
        callback++;
      }
  }
  */
}
MARK_END_OF_FUNCTION(restore)

#define Test86MSByte(b) ((b) == 0 || (b) == 0xFF)
static size_t x86_filter(BYTE *data, size_t size) {
  uint32_t state = 0;
  uint32_t ip = 0;
  const BYTE kMaskToAllowedStatus[8] = {1, 1, 1, 0, 1, 0, 0, 0};
  const BYTE kMaskToBitNumber[8] = {0, 1, 2, 2, 3, 3, 3, 3};
  size_t bufferPos = 0, prevPosT;
  uint32_t prevMask = state & 0x7;
  if (size < 5)
    return 0;
  ip += 5;
  prevPosT = (size_t)0 - 1;
  for (;;) {
    BYTE *p = data + bufferPos;
    BYTE *limit = data + size - 4;
    for (; p < limit; p++)
      if ((*p & 0xFE) == 0xE8)
        break;
    bufferPos = (size_t)(p - data);
    if (p >= limit)
      break;
    prevPosT = bufferPos - prevPosT;
    if (prevPosT > 3)
      prevMask = 0;
    else {
      prevMask = (prevMask << ((int)prevPosT - 1)) & 0x7;
      if (prevMask != 0) {
        BYTE b = p[4 - kMaskToBitNumber[prevMask]];
        if (!kMaskToAllowedStatus[prevMask] || Test86MSByte(b)) {
          prevPosT = bufferPos;
          prevMask = ((prevMask << 1) & 0x7) | 1;
          bufferPos++;
          continue;
        }
      }
    }
    prevPosT = bufferPos;
    if (Test86MSByte(p[4])) {
      uint32_t src = ((uint32_t)p[4] << 24) | ((uint32_t)p[3] << 16) |
                     ((uint32_t)p[2] << 8) | ((uint32_t)p[1]);
      uint32_t dest;
      for (;;) {
        BYTE b;
        int index;
        dest = src - (ip + (uint32_t)bufferPos);
        if (prevMask == 0)
          break;
        index = kMaskToBitNumber[prevMask] * 8;
        b = (BYTE)(dest >> (24 - index));
        if (!Test86MSByte(b))
          break;
        src = dest ^ ((1 << (32 - index)) - 1);
      }
      p[4] = (BYTE)(~(((dest >> 24) & 1) - 1));
      p[3] = (BYTE)(dest >> 16);
      p[2] = (BYTE)(dest >> 8);
      p[1] = (BYTE)dest;
      bufferPos += 5;
    } else {
      prevMask = ((prevMask << 1) & 0x7) | 1;
      bufferPos++;
    }
  }
  prevPosT = bufferPos - prevPosT;
  state = ((prevPosT > 3) ? 0 : ((prevMask << ((int)prevPosT - 1)) & 0x7));
  return bufferPos;
}
MARK_END_OF_FUNCTION(x86_filter)

static void depack_fnc(stubcode *p, INT_PTR base_offset) {
  if (p->IsDepacked == 1)
    return;
  DWORD *fixup = (DWORD *)&p->mentry;
  DWORD *fixup_end = (DWORD *)&p->OriginalImports;
  while (fixup < fixup_end)
    *fixup++ += base_offset;
  DWORD OldP = NULL;
 
  typedef int(_stdcall* tdefilt)(PVOID, DWORD);
  tdefilt codefilt = (tdefilt)p->codefilter;
  typedef int(_stdcall* tdecomp)(PVOID, PVOID);
  tdecomp decomp = (tdecomp)p->depacker;


  unsigned char *input =
      (unsigned char *)p->virtualalloc(NULL, p->sizepacked, MEM_COMMIT, PAGE_READWRITE);
  p->rtlmovemem(input, (LPVOID)p->packed_ptr, p->sizepacked);
  p->virtualprotect((LPVOID)p->packed_ptr, p->sizeunpacked, PAGE_EXECUTE_READWRITE,
           &OldP);

  decomp((LPVOID)p->packed_ptr, (unsigned char *)input);
  
  codefilt((LPVOID)(p->packed_ptr), p->code_locsz);
  p->virtualfree(input, 0, MEM_RELEASE);
  typedef void(_stdcall * trestore)(LPVOID, LPVOID);
  trestore restore = (trestore)p->restore;
  restore(p, (LPVOID)base_offset);


  

  

  DWORD old_protect;
  PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)p->ImageBase;
  PIMAGE_NT_HEADERS pNTHeader =
      (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew);
  IMAGE_OPTIONAL_HEADER* pOptHeader = (IMAGE_OPTIONAL_HEADER*)&pNTHeader->OptionalHeader;
  p->virtualprotect((LPVOID)pOptHeader, pNTHeader->FileHeader.SizeOfOptionalHeader,
           PAGE_READWRITE, &old_protect);
  IMAGE_DATA_DIRECTORY* resource_dir = (IMAGE_DATA_DIRECTORY*)&pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
  resource_dir->Size = p->OriginalResourcesSize;
  resource_dir->VirtualAddress = p->OriginalResources;
  IMAGE_DATA_DIRECTORY *import_dir =
      (IMAGE_DATA_DIRECTORY *) import_dir =(IMAGE_DATA_DIRECTORY*)&pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
  import_dir->Size = p->OriginalImportsSize;
  import_dir->VirtualAddress = p->OriginalImports;
  p->virtualprotect((LPVOID)pOptHeader, pNTHeader->FileHeader.SizeOfOptionalHeader,
           old_protect, &old_protect);

  if (p->tls_oldindexrva)
      *(DWORD*)(p->tls_oldindexrva + p->ImageBase) = p->tls_index;

  if (p->tls_callbackold) {
      PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)(p->tls_callbackold + p->ImageBase);
      PIMAGE_TLS_CALLBACK* callback_bckup =
          (PIMAGE_TLS_CALLBACK*)(p->TlsCallbackNew + p->ImageBase);
      while (*callback) {
          *callback_bckup = *callback;
          callback_bckup++;
          callback++;
      }
      callback_bckup =
          (PIMAGE_TLS_CALLBACK*)(p->TlsCallbackNew + p->ImageBase);
      (*callback_bckup)((LPVOID)p->ImageBase, DLL_PROCESS_ATTACH, NULL);
  }
  p->IsDepacked = 1;
}
MARK_END_OF_FUNCTION(depack_fnc)
}
/*

CodeGenerator code;
code.mov(eax, 5);
code.ret();

*/
class Bootstrapper : public Xbyak::CodeGenerator {
public:
  Bootstrapper(int packer_struct, int main_loadcode, int OEP) {
    //altered by relocation
    mov(ebx, 0);
    jmp(".tls");
    //TLS callback
    ret(0xC);
    L(".tls");
    push(ebx); //offset made by relocation
    lea(eax, ptr[ebx + packer_struct]);
    push(eax);
    lea(eax, ptr[ebx + main_loadcode]);
    call(eax);
    lea(eax, ptr[ebx + OEP]);
    jmp(eax);
  }
};

unsigned int get_bootloadersz() {
  Bootstrapper code(0x1988, 0x1988, 0x1988);
  return code.getSize();
}

extern "C" DWORD _stdcall get_frdepackersize();
extern "C" DWORD _stdcall get_frdepackerptr();

enum packsize {
  SIZE_BOOTSTRAP = 0,
  SIZE_LOADER,
  SIZE_RESTORE,
  SIZE_CODEFILTER,
  SIZE_DECOMPRESS,
  DEPACKER_SIZES
};
DWORD sfunc[DEPACKER_SIZES] = {0};
int stubcode_sz() {
  sfunc[SIZE_BOOTSTRAP] = get_bootloadersz();
  sfunc[SIZE_LOADER] = SIZEOF_FUNCTION(depack_fnc);
  sfunc[SIZE_RESTORE] = SIZEOF_FUNCTION(restore);
  sfunc[SIZE_CODEFILTER] = SIZEOF_FUNCTION(x86_filter);
  sfunc[SIZE_DECOMPRESS] = get_frdepackersize();
  int stubsize = sizeof(stubcode);
  for (int i = 0; i < DEPACKER_SIZES; i++)
    stubsize += sfunc[i];
  return stubsize;
}

unsigned char *build_stub(int OEP, int imagebase, int section_va,
                          int *stubsize) {
  stubcode_ptr.IsDepacked = 0;
  stubcode_ptr.ImageBase = imagebase;
  DWORD decompress_ptr = get_frdepackerptr();
  DWORD main_depack =
      imagebase + section_va + sizeof(stubcode) + sfunc[SIZE_BOOTSTRAP];
  DWORD pointer_tbl = imagebase + section_va + sfunc[SIZE_BOOTSTRAP];
  Bootstrapper shellcode(pointer_tbl, main_depack, imagebase + OEP);
  *stubsize = sizeof(stubcode) + sfunc[SIZE_BOOTSTRAP] + sfunc[SIZE_LOADER] +
              sfunc[SIZE_RESTORE] + sfunc[SIZE_CODEFILTER] +
              sfunc[SIZE_DECOMPRESS];
  BYTE *psection = (BYTE *)malloc(*stubsize);
  memset(psection, 0x90, *stubsize);
  memcpy(psection, shellcode.getCode(), sfunc[SIZE_BOOTSTRAP]);
  BYTE *psection2 = psection + sfunc[SIZE_BOOTSTRAP] + sizeof(stubcode);
  memcpy((LPVOID)psection2, (LPVOID)&depack_fnc, sfunc[SIZE_LOADER]);
  psection2 += sfunc[SIZE_LOADER];
  memcpy((LPVOID)psection2, (LPVOID)&restore, sfunc[SIZE_RESTORE]);
  psection2 += sfunc[SIZE_RESTORE];
  memcpy((LPVOID)psection2, (LPVOID)&x86_filter, sfunc[SIZE_CODEFILTER]);
  psection2 += sfunc[SIZE_CODEFILTER];
  memcpy((LPVOID)psection2, (LPVOID)decompress_ptr, sfunc[SIZE_DECOMPRESS]);

  stubcode_ptr.mentry = main_depack;
  main_depack += sfunc[SIZE_LOADER];
  stubcode_ptr.restore = main_depack;
  main_depack += sfunc[SIZE_RESTORE];
  stubcode_ptr.codefilter = main_depack;
  main_depack += sfunc[SIZE_CODEFILTER];
  stubcode_ptr.depacker = main_depack;
  memcpy(psection + sfunc[SIZE_BOOTSTRAP], &stubcode_ptr, sizeof(stubcode));
  return psection;
}
