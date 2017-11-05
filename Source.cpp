#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <string>
#include <fstream>

#define SIZE 500

DWORD ProcessId;
BOOL isDLLInjected = false;

static DWORD FindWindowProcessId_main(char* fd_name)
{
	HWND hWindow = FindWindowA(0, (fd_name)); // Find the window
	ProcessId = GetWindowThreadProcessId(hWindow, &ProcessId); // Get the Proceess Id of fd_name
	if (hWindow) return TRUE;
	else {
		std::cerr << "\nCould Not Find Process ID";
		return FALSE;
	}
	return FALSE;
}

BOOL InjectDLLToProcess_main(DWORD procId, PCHAR dll_path)
{
	// Open the app process ALLOWED: ALL_ACCESS
	char si[SIZE];
	HANDLE applProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, procId);
	if (applProcess)
	{
		// handle kernel32 lib
		LPVOID LibAddressToLoad_KERNEL32 = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.lib"), "LoadLibraryA");
		if (!LibAddressToLoad_KERNEL32)
			return FALSE; // BASIC ERROR HANDLING TO CHECK IF LibAddressToLoad_KERNEL32 is invalid
		LPVOID Location_LIBRARYLoader = VirtualAllocEx(applProcess, 0, strlen(dll_path),
			MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (Location_LIBRARYLoader == NULL) return FALSE;

		// Create Remote Execution thread
		HANDLE rmThreadExecution = CreateRemoteThread(applProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LibAddressToLoad_KERNEL32,
			Location_LIBRARYLoader, NULL, NULL);
		if (!WriteProcessMemory(applProcess, Location_LIBRARYLoader, dll_path, strlen(dll_path) + 1, NULL)) 
			return FALSE;
		// SINGLE OBJECT WAIT PERIOD
		WaitForSingleObject(applProcess, INFINITE);
		// FREE DLL PATH
		VirtualFreeEx(applProcess, Location_LIBRARYLoader, strlen(dll_path), MEM_RELEASE);

	}
	// Close The Handlers
	CloseHandle(applProcess);
	return FALSE;
}

static BOOL WriteDataToFile_main(const char* file_name)
{
	std::ofstream writeFile; // FILE OBJECT
	writeFile.open(file_name);
	if (writeFile) // IF THE ITS VALID, WRITE THE DATA
	{
		isDLLInjected = true;
		// Write The Data to the file
		writeFile << "\nDLL DATA\n";
		writeFile << "Process ID: " << ProcessId << std::endl;
		if (isDLLInjected)
			writeFile << "INJECTION STATUS: " << isDLLInjected << "\n";
		std::cout << "Data output Written To: " << file_name << std::endl;
		writeFile.close(); // Close the file
	}
	else if (!writeFile) return FALSE;

}

int main()
{
	char* fd_name = "Calculator";
	const char* file_name = "injection_otpt.txt";

	if (FindWindowProcessId_main(fd_name))
	{
		std::cout << "Process ID of: " << fd_name << ": " << ProcessId << std::endl;

		if (InjectDLLToProcess_main(ProcessId, "C:\\VulnDLL.dll")) // Check for validation
			isDLLInjected = true;
			std::cout << "DLL Injected Successfully!\n" << std::endl;
			// Write the Data to the file
			WriteDataToFile_main(file_name);
			
	}
	else if (!FindWindowProcessId_main(fd_name)) std::cerr << "\n\nCannot Inject Dll" << std::endl;
	
	system("pause");
}