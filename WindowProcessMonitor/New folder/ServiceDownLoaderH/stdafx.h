// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <windows.h>
#include <winternl.h>

#define DWORDV(arg) *((DWORD*)arg)
#define	WORDV(arg)	*((WORD*)arg)
#define BYTEV(arg)	*((BYTE*)arg)

typedef DWORD (__stdcall *pFn_Void)();//RHC0824
typedef DWORD (__stdcall *pFn_DW_DW)(DWORD);
typedef DWORD (__stdcall *pFn_DW_DWDW)(DWORD, DWORD);//RHC0824
typedef DWORD (__stdcall *pFn_DW_DWDWDW)(DWORD, DWORD, DWORD);//RHC0824
typedef DWORD (__stdcall *pFn_DW_DWDWDWDW)(DWORD, DWORD, DWORD, DWORD);//RHI0825
typedef DWORD (__stdcall *pFn_DW_DWDWDWDWDW)(DWORD, DWORD, DWORD, DWORD, DWORD);//RHC0824
typedef DWORD (__stdcall *pFn_DW_DWDWDWDWDWDW)(DWORD, DWORD, DWORD, DWORD, DWORD, DWORD);//RHC0824

#define MAX_ACE_COUNT 128
typedef struct _HOOK_ACL_
{
	ULONG                   Count;
	BOOL                    IsExclusive;
	ULONG                   Entries[MAX_ACE_COUNT];
}HOOK_ACL;

typedef struct _LOCAL_HOOK_INFO_* PLOCAL_HOOK_INFO;
typedef struct _HOOK_TRACE_INFO_
{
	PLOCAL_HOOK_INFO        Link;
}HOOK_TRACE_INFO, *TRACED_HOOK_HANDLE;

typedef struct _LOCAL_HOOK_INFO_
{
	PLOCAL_HOOK_INFO        Next;
	ULONG					NativeSize;
	UCHAR*					TargetProc;
	ULONGLONG				TargetBackup;
	ULONGLONG				TargetBackup_x64;
	ULONGLONG				HookCopy;
	ULONG					EntrySize;
	UCHAR*					Trampoline;
	ULONG					HLSIndex;
	ULONG					HLSIdent;
	void*					Callback;
	HOOK_ACL				LocalACL;
	ULONG                   Signature;
	TRACED_HOOK_HANDLE      Tracking;

	void*					RandomValue; // fixed
	void*					HookIntro; // fixed
	UCHAR*					OldProc; // fixed
	UCHAR*					HookProc; // fixed
	void*					HookOutro; // fixed
	int*					IsExecutedPtr; // fixed
}LOCAL_HOOK_INFO, *PLOCAL_HOOK_INFO;

typedef NTSTATUS MyLhInstallHook(void* InEntryPoint, void* InHookProc, void* InCallback, TRACED_HOOK_HANDLE OutHandle);
typedef NTSTATUS MyLhSetExclusiveACL(ULONG* InThreadIdList,	ULONG InThreadCount, TRACED_HOOK_HANDLE InHandle);
typedef NTSTATUS MyLhUninstallAllHooks();


// TODO: reference additional headers your program requires here
