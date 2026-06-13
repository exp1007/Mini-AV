#include "../Globals.h"
#include "Logging.h"

#include <atomic>
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
// Atomic so Log() can bail without touching LogMutex once logging is disabled —
// this also shrinks the window in which a writer can be mid-console-write.
static std::atomic<bool> IsInitialized{ false };

void Initialize()
{
	std::lock_guard<std::mutex> Lock(LogMutex);
	if (IsInitialized.load()) {
		return;
	}

	if (!AllocConsole()) {
		return;
	}

	SetConsoleTitleA("Mini-AV Console");

	// Enable QuickEdit so the user can mark/select log text with the mouse and copy
	// it (that flag is what unlocks mouse selection + Enter-to-copy). Trade-off,
	// accepted on purpose: while a selection is held the console pauses ALL output,
	// so a worker thread can block inside printf while holding LogMutex and Shutdown()
	// will wait on that lock until the selection is released. That is a transient
	// pause (finish/clear the selection and it resumes), not a permanent hang — and
	// being able to copy the logs is worth it. ENABLE_QUICK_EDIT_MODE only takes
	// effect alongside ENABLE_EXTENDED_FLAGS.
	const HANDLE HInput = GetStdHandle(STD_INPUT_HANDLE);
	if (HInput != INVALID_HANDLE_VALUE && HInput != nullptr) {
		DWORD InputMode = 0;
		if (GetConsoleMode(HInput, &InputMode)) {
			InputMode |= ENABLE_EXTENDED_FLAGS | ENABLE_QUICK_EDIT_MODE | ENABLE_INSERT_MODE;
			SetConsoleMode(HInput, InputMode);
		}
	}

	// Grow the scrollback buffer so older log lines stay scrollable (the default
	// ~300-line height truncates history). Keep the existing width.
	const HANDLE HOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	if (HOutput != INVALID_HANDLE_VALUE && HOutput != nullptr) {
		CONSOLE_SCREEN_BUFFER_INFO BufferInfo{};
		if (GetConsoleScreenBufferInfo(HOutput, &BufferInfo)) {
			COORD BufferSize = BufferInfo.dwSize;
			BufferSize.Y = 9000;
			SetConsoleScreenBufferSize(HOutput, BufferSize);
		}
	}

	FILE* Stream = nullptr;
	freopen_s(&Stream, "CONOUT$", "w", stdout);
	freopen_s(&Stream, "CONOUT$", "w", stderr);
	freopen_s(&Stream, "CONIN$", "r", stdin);

	IsInitialized = true;
}

void Shutdown()
{
	std::lock_guard<std::mutex> Lock(LogMutex);
	if (!IsInitialized) {
		return;
	}

	FILE* Stream = nullptr;
	freopen_s(&Stream, "NUL", "w", stdout);
	freopen_s(&Stream, "NUL", "w", stderr);
	freopen_s(&Stream, "NUL", "r", stdin);

	FreeConsole();

	IsInitialized = false;
}

void Log(const char* File, int Line, WORD Color, const char* Fmt, ...)
{
	// Fast path: skip the lock entirely when the console is off.
	if (!IsInitialized.load()) {
		return;
	}

	std::lock_guard<std::mutex> Lock(LogMutex);
	if (!IsInitialized.load()) {
		return;
	}

	SYSTEMTIME Time;
	GetLocalTime(&Time);

	const HANDLE HConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	if (HConsole == INVALID_HANDLE_VALUE || HConsole == nullptr) {
		return;
	}

	CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo{};
	if (!GetConsoleScreenBufferInfo(HConsole, &ConsoleInfo)) {
		return;
	}

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