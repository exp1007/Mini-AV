#include "../Globals.h"
#include "Logging.h"

#include <chrono>
#include <ctime>
#include <mutex>

namespace {

std::mutex UiLogsMutex;

}

void Logs::Add(std::string Data)
{
	auto Now = std::chrono::system_clock::now();
	const std::time_t NowC = std::chrono::system_clock::to_time_t(Now);
	char TimeBuffer[32];
	std::strftime(TimeBuffer, sizeof(TimeBuffer), "[%Y-%m-%d %H:%M:%S] ", std::localtime(&NowC));
	const std::string FormattedString = std::string(TimeBuffer) + Data;

	std::lock_guard<std::mutex> Lock(UiLogsMutex);
	Globals::Logs.push_back(FormattedString);
}

std::vector<std::string> Logs::GetSnapshot()
{
	std::lock_guard<std::mutex> Lock(UiLogsMutex);
	return Globals::Logs;
}

namespace TerminalLogs {

static std::mutex LogMutex;
static bool IsInitialized = false;

void Initialize()
{
	std::lock_guard<std::mutex> Lock(LogMutex);
	if (IsInitialized) {
		return;
	}

	AllocConsole();
	SetConsoleTitleA("Mini-AV Console");
	freopen_s(reinterpret_cast<FILE**>(stdout), "CONOUT$", "w", stdout);
	freopen_s(reinterpret_cast<FILE**>(stderr), "CONOUT$", "w", stderr);
	freopen_s(reinterpret_cast<FILE**>(stdin), "CONIN$", "r", stdin);

	IsInitialized = true;
}

void Shutdown()
{
	std::lock_guard<std::mutex> Lock(LogMutex);
	if (!IsInitialized) {
		return;
	}

	PostMessageA(GetConsoleWindow(), WM_CLOSE, 0, 0);
	FreeConsole();

	IsInitialized = false;
}

void Log(const char* File, int Line, WORD Color, const char* Fmt, ...)
{
	std::lock_guard<std::mutex> Lock(LogMutex);
	if (!IsInitialized) {
		return;
	}

	SYSTEMTIME Time;
	GetLocalTime(&Time);

	HANDLE HConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
	GetConsoleScreenBufferInfo(HConsole, &ConsoleInfo);
	const WORD OriginalAttrs = ConsoleInfo.wAttributes;

	const char* FileName = strrchr(File, '\\');
	FileName = FileName ? FileName + 1 : File;

	char Message[2048]{};
	va_list Args;
	va_start(Args, Fmt);
	const int MessageLen = vsnprintf(Message, sizeof(Message), Fmt, Args);
	va_end(Args);

	printf("[%02d:%02d:%02d] ", Time.wHour, Time.wMinute, Time.wSecond);

	SetConsoleTextAttribute(HConsole, Color);
	printf("%s:%d:", FileName, Line);
	SetConsoleTextAttribute(HConsole, OriginalAttrs);
	printf(" ");

	if (MessageLen >= 0) {
		printf("%s", Message);
	}
	printf("\n");
	fflush(stdout);
}

}