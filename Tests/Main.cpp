#include <Windows.h>
#include <iostream>
#include <Psapi.h>

void PrintMenu() {
	std::cout << "------- POC -------" << std::endl;
	std::cout << "0. Memory access" << std::endl;
	std::cout << "1. Soon" << std::endl;
}

// Memory access stuff

uintptr_t GetBaseAddress(DWORD pid) {
	uintptr_t baseAddress = 0;
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (hProcess) {
		HMODULE hMods[1024];
		DWORD cbNeeded;
		if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
			baseAddress = reinterpret_cast<uintptr_t>(hMods[0]);  // First module is the EXE
		}
		CloseHandle(hProcess);
	}
	return baseAddress;
}

void MemeoryAccess(DWORD PID, HANDLE* hProc) {
	*hProc = OpenProcess(PROCESS_ALL_ACCESS, false, PID);
	if (hProc)
		std::cout << "Process handle created successfully: " << *hProc << std::endl;
	else
		std::cout << "Process handle failed" << std::endl;

	std::cout << "Press backspace for other tests" << std::endl;

	uintptr_t baseAddr = GetBaseAddress(PID);
	char localBuffer[255] = { };
	while (!GetAsyncKeyState(VK_BACK)) {
		if(ReadProcessMemory(*hProc, (void*)baseAddr, localBuffer, 255, nullptr))
			std::cout << "Main module data (255 bytes): " << localBuffer << std::endl;
		else
			std::cout << "Can't read memory" << std::endl;

		Sleep(500);
	}
}

int main() {
	uint32_t selection = 0;
	DWORD PID = -1;
	HANDLE hProc = NULL;

	std::cout << "Select target process (PID): ";
	std::cin >> PID;

	do {
		system("cls");
		PrintMenu();

		std::cout << std::endl << "Choose your option : ";
		std::cin >> selection;

		switch (selection)
		{
		case 0:
			MemeoryAccess(PID, &hProc);
		default:
			break;
		}
	} while (true);
}