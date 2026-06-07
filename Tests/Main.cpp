#include <Windows.h>
#include <iostream>
#include <Psapi.h>
#include <intrin.h>      // __readgsqword, __rdtsc, __rdtscp

#pragma comment(lib, "user32.lib")

void PrintMenu() {
	std::cout << "------- POC -------" << std::endl;
	std::cout << "0. Memory access" << std::endl;
	std::cout << "1. Anti-debug checks" << std::endl;
}

// ---- Anti-debug sample ----------------------------------------------------
// Deliberately exercises several Check Point (anti-debug.checkpoint.com)
// techniques so the compiled binary carries the matching byte patterns,
// imports and strings. This is a *true-positive* specimen for the AV's
// AntiDebugEngine — not production logic. Results are funneled into a volatile
// sink so the optimizer can't elide the reads in a Release build.

static volatile unsigned long long g_sink = 0;

void AntiDebugChecks() {
	int detections = 0;

	// (1) PEB->BeingDebugged via direct gs:[60h] read (no API). __readgsqword
	//     emits `mov rax, gs:[60h]`; the +2 byte read is BeingDebugged.
	const auto peb = static_cast<const unsigned char*>(
		reinterpret_cast<void*>(__readgsqword(0x60)));
	const unsigned char beingDebugged = peb[0x02];
	g_sink += beingDebugged;
	if (beingDebugged) { std::cout << "[+] PEB.BeingDebugged set\n"; ++detections; }

	// (2) PEB->NtGlobalFlag (PEB+0xBC on x64): debug heap flags get set.
	const unsigned long ntGlobalFlag = *reinterpret_cast<const unsigned long*>(peb + 0xBC);
	g_sink += ntGlobalFlag;
	if (ntGlobalFlag & 0x70) { std::cout << "[+] NtGlobalFlag debug bits set\n"; ++detections; }

	// (3) KUSER_SHARED_DATA.KdDebuggerEnabled — fixed address 0x7FFE02D4.
	const unsigned char kdEnabled = *reinterpret_cast<const unsigned char*>(0x7FFE02D4ull);
	g_sink += kdEnabled;
	if (kdEnabled & 0x03) { std::cout << "[+] Kernel debugger present\n"; ++detections; }

	// (4) rdtsc / rdtscp timing gate.
	unsigned int aux = 0;
	const unsigned long long t0 = __rdtsc();
	g_sink += __rdtscp(&aux);
	if (__rdtsc() - t0 > 0x100000ull) { std::cout << "[+] Timing anomaly (single-stepped?)\n"; ++detections; }

	// (5) Win32 API layer: CheckRemoteDebuggerPresent (strong) + IsDebuggerPresent (weak).
	BOOL remote = FALSE;
	CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
	if (remote) { std::cout << "[+] CheckRemoteDebuggerPresent\n"; ++detections; }
	if (IsDebuggerPresent()) { std::cout << "[+] IsDebuggerPresent\n"; ++detections; }

	// (6) FindWindow for a known debugger window class + OutputDebugString.
	if (FindWindowA("OLLYDBG", nullptr) != nullptr) { std::cout << "[+] OllyDbg window\n"; ++detections; }
	OutputDebugStringA("AntiDebugChecks probe\n");

	std::cout << "Anti-debug checks complete. Detections: " << detections << std::endl;
	std::cout << "(sink=" << g_sink << ")" << std::endl;
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
			break;
		case 1:
			AntiDebugChecks();
			system("pause");
			break;
		default:
			break;
		}
	} while (true);
}