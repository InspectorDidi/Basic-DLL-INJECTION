// dll_injection.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <string>
#include <stdlib.h>

#define _UNICODE

BOOL InjectDLLToProcess_dllmain(DWORD procId, char* path_to_dll)
{
	// Open a handle to target process
	HANDLE ProcDLLHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, procId);
	if (ProcDLLHandle) // Check if the HANDLE is valid
	{
		// make a copy of kernel32.dll
		LPVOID LoadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
		LPVOID LoadLocation = VirtualAllocEx(ProcDLLHandle, 0, strlen(path_to_dll), MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE);
		HANDLE RemoteThread = CreateRemoteThread(ProcDLLHandle, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddr,
			LoadLocation, NULL, NULL); // Execute remote threading on target program
		WaitForSingleObject(RemoteThread, INFINITE);
		// free they path to the DLL
		VirtualFreeEx(ProcDLLHandle, LoadLocation, strlen(path_to_dll), MEM_RELEASE);
		// Close HANDLERS
		CloseHandle(RemoteThread);
		CloseHandle(ProcDLLHandle);
		return TRUE;
	}

	return FALSE;
}

DWORD ReturnProcessId(char* ProcessName)
{
	PROCESSENTRY32 ProcEntry = { 0 };
	HANDLE lehandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	DWORD pid = 0;
	ProcEntry.dwSize = sizeof(PROCESSENTRY32);

	if (lehandle != NULL)
	{
		if (Process32First(lehandle, &ProcEntry))
			do
			{
				if (!strcmp((PCHAR)ProcEntry.szExeFile, ProcessName)) 
					pid = ProcEntry.th32ProcessID;
				break;

			} while (Process32Next(lehandle, &ProcEntry));
	}

	return pid;
}

int main()
{
	DWORD ProcessID = ReturnProcessId("notepad++.exe");
	if (ProcessID)
	{
		InjectDLLToProcess_dllmain(ProcessID, "C:\\Users\joshs\source\repos\VulnDLL\Debug\VulnDLL.dll");
		std::cout << "DLL Injected Successfully!" << std::endl;
	}
	else if  (!ProcessID) {
		std::cerr << "[-] Could Not Inject DLL" << std::endl;
	}
	system("pause");
    return 0;
}

