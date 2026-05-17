#include "Scanner.h"

#include "../../Alerts/Alerts.h"
#include "../../Logging/Logging.h"

#include <Windows.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cwchar>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

namespace {

std::mutex g_queueMutex;
std::condition_variable g_queueCv;
std::queue<MINIAV_CREATE_DECISION_REQUEST> g_queue;
std::unordered_set<std::wstring> g_pendingKeys;
std::unordered_set<std::wstring> g_recentKeys;
std::atomic<bool> g_workerStop{ false };
std::thread g_worker;

constexpr size_t kMaxRecentPaths = 256;
constexpr const WCHAR kWindowsAppsSegment[] = L"\\Microsoft\\WindowsApps\\";

static uint32_t Fnv1a32(const unsigned char* Data, size_t Length)
{
	uint32_t hash = 2166136261u;
	for (size_t i = 0; i < Length; ++i) {
		hash ^= Data[i];
		hash *= 16777619u;
	}
	return hash;
}

static std::wstring NtPathToWin32(const std::wstring& NtPath)
{
	if (NtPath.size() < 8 || NtPath.compare(0, 8, L"\\Device\\") != 0) {
		return NtPath;
	}

	WCHAR drive[3] = L"X:";
	WCHAR deviceName[512];

	for (WCHAR letter = L'A'; letter <= L'Z'; ++letter) {
		drive[0] = letter;
		if (QueryDosDeviceW(drive, deviceName, static_cast<DWORD>(sizeof(deviceName) / sizeof(deviceName[0]))) == 0) {
			continue;
		}

		const size_t deviceLen = wcslen(deviceName);
		if (NtPath.size() < deviceLen || NtPath.compare(0, deviceLen, deviceName) != 0) {
			continue;
		}

		if (NtPath.size() > deviceLen && NtPath[deviceLen] != L'\\') {
			continue;
		}

		return std::wstring(drive) + NtPath.substr(deviceLen);
	}

	return L"";
}

static std::wstring ToLower(std::wstring Value)
{
	std::transform(Value.begin(), Value.end(), Value.begin(), [](wchar_t Ch) {
		return static_cast<wchar_t>(towlower(Ch));
	});
	return Value;
}

static bool PathContainsInsensitive(const std::wstring& Path, const WCHAR* Segment)
{
	if (Segment == nullptr || Segment[0] == L'\0') {
		return false;
	}

	const std::wstring pathLower = ToLower(Path);
	const std::wstring segmentLower = ToLower(std::wstring(Segment));
	return pathLower.find(segmentLower) != std::wstring::npos;
}

static bool ShouldSkipScanPath(const std::wstring& Path)
{
	return PathContainsInsensitive(Path, kWindowsAppsSegment);
}

static std::wstring MakeDedupKey(const MINIAV_CREATE_DECISION_REQUEST& Request)
{
	const size_t charCount = (Request.PathLengthChars > 0 && Request.PathLengthChars < MINIAV_MAX_PATH_CHARS)
		? Request.PathLengthChars
		: wcsnlen(Request.Path, MINIAV_MAX_PATH_CHARS);

	std::wstring key(Request.Path, charCount);
	return ToLower(key);
}

static const WCHAR* RequestPathForLog(const MINIAV_CREATE_DECISION_REQUEST& Request)
{
	return (Request.Path[0] != L'\0') ? Request.Path : L"(empty)";
}

static void TrimRecentKeys()
{
	while (g_recentKeys.size() > kMaxRecentPaths) {
		g_recentKeys.erase(g_recentKeys.begin());
	}
}

static std::wstring StripExtendedPathPrefix(const std::wstring& Path)
{
	if (Path.rfind(L"\\\\?\\", 0) == 0) {
		return Path.substr(4);
	}
	return Path;
}

static std::wstring ResolveFinalDosPath(const std::wstring& Win32Path)
{
	HANDLE file = CreateFileW(
		Win32Path.c_str(),
		FILE_READ_ATTRIBUTES,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		nullptr,
		OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS,
		nullptr);

	if (file == INVALID_HANDLE_VALUE) {
		return L"";
	}

	std::vector<WCHAR> buffer(MAX_PATH);
	DWORD length = GetFinalPathNameByHandleW(
		file,
		buffer.data(),
		static_cast<DWORD>(buffer.size()),
		FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);

	if (length == 0) {
		CloseHandle(file);
		return L"";
	}

	if (length >= buffer.size()) {
		buffer.resize(length + 1);
		length = GetFinalPathNameByHandleW(
			file,
			buffer.data(),
			static_cast<DWORD>(buffer.size()),
			FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
		if (length == 0 || length >= buffer.size()) {
			CloseHandle(file);
			return L"";
		}
	}

	CloseHandle(file);
	return StripExtendedPathPrefix(std::wstring(buffer.data(), length));
}

static void ScanBlockedFile(const MINIAV_CREATE_DECISION_REQUEST& Request)
{
	const std::wstring ntPath(Request.Path);
	const std::wstring win32Path = NtPathToWin32(ntPath);

	if (win32Path.empty()) {
		LOG_ERROR("Scanner: failed NT path conversion for %ls", ntPath.c_str());
		Logs::Add("Scanner: failed NT path conversion.");
		return;
	}

	std::wstring scanPath = ResolveFinalDosPath(win32Path);
	if (scanPath.empty()) {
		scanPath = win32Path;
	}

	HANDLE file = CreateFileW(
		scanPath.c_str(),
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr);

	if (file == INVALID_HANDLE_VALUE) {
		const DWORD err = GetLastError();
		LOG_ERROR("Scanner: CreateFile failed path=%ls err=%lu", scanPath.c_str(), err);
		Logs::Add("Scanner: could not open blocked file (err " + std::to_string(err) + ").");
		return;
	}

	LARGE_INTEGER fileSize{};
	if (!GetFileSizeEx(file, &fileSize)) {
		const DWORD err = GetLastError();
		CloseHandle(file);
		LOG_ERROR("Scanner: GetFileSizeEx failed path=%ls err=%lu", scanPath.c_str(), err);
		return;
	}

	constexpr DWORD kReadChunk = 4096;
	std::vector<unsigned char> buffer(kReadChunk);
	DWORD bytesRead = 0;

	const BOOL readOk = ReadFile(file, buffer.data(), kReadChunk, &bytesRead, nullptr);
	CloseHandle(file);

	if (!readOk) {
		const DWORD err = GetLastError();
		LOG_ERROR("Scanner: ReadFile failed path=%ls err=%lu", scanPath.c_str(), err);
		return;
	}

	const uint32_t hash = Fnv1a32(buffer.data(), bytesRead);

	LOG_SUCCESS(
		"Scanner: read blocked file pid=%lu subtype=%lu path=%ls size=%lld bytes read=%lu fnv1a=0x%08X",
		Request.ProcessId,
		Request.OperationSubtype,
		scanPath.c_str(),
		static_cast<long long>(fileSize.QuadPart),
		bytesRead,
		hash);

	Logs::Add(
		"Scanner: opened blocked file size=" + std::to_string(fileSize.QuadPart) +
		" hash=0x" + std::to_string(hash));

	char alertPath[MAX_PATH * 2]{};
	(void)WideCharToMultiByte(
		CP_UTF8,
		0,
		scanPath.c_str(),
		-1,
		alertPath,
		static_cast<int>(sizeof(alertPath)),
		nullptr,
		nullptr);
	Alerts::Add(std::string("Blocked file scanned: ") + alertPath, AlertRisk::medium);
}

static void WorkerLoop()
{
	for (;;) {
		MINIAV_CREATE_DECISION_REQUEST item{};

		{
			std::unique_lock<std::mutex> lock(g_queueMutex);
			g_queueCv.wait(lock, [] {
				return g_workerStop.load() || !g_queue.empty();
			});

			if (g_workerStop.load() && g_queue.empty()) {
				break;
			}

			if (g_queue.empty()) {
				continue;
			}

			item = g_queue.front();
			g_queue.pop();
		}

		LOG_INFO(
			"Scanner: processing blocked file pid=%lu subtype=%lu path=%ls",
			item.ProcessId,
			item.OperationSubtype,
			RequestPathForLog(item));

		const std::wstring dedupKey = MakeDedupKey(item);
		ScanBlockedFile(item);

		{
			std::lock_guard<std::mutex> lock(g_queueMutex);
			g_pendingKeys.erase(dedupKey);
			g_recentKeys.insert(dedupKey);
			TrimRecentKeys();
		}
	}
}

}

namespace Scanner {

void Start()
{
	if (g_worker.joinable()) {
		return;
	}

	g_workerStop = false;
	g_worker = std::thread(WorkerLoop);
}

void Stop()
{
	g_workerStop = true;
	g_queueCv.notify_all();

	if (g_worker.joinable()) {
		g_worker.join();
	}

	{
		std::lock_guard<std::mutex> lock(g_queueMutex);
		std::queue<MINIAV_CREATE_DECISION_REQUEST> empty;
		g_queue.swap(empty);
		g_pendingKeys.clear();
		g_recentKeys.clear();
	}
}

void EnqueueBlockedFile(const MINIAV_CREATE_DECISION_REQUEST& Request)
{
	const std::wstring dedupKey = MakeDedupKey(Request);

	if (ShouldSkipScanPath(dedupKey)) {
		LOG_INFO(
			"Scanner: ignored blocked file (WindowsApps) pid=%lu subtype=%lu path=%ls",
			Request.ProcessId,
			Request.OperationSubtype,
			RequestPathForLog(Request));
		return;
	}

	{
		std::lock_guard<std::mutex> lock(g_queueMutex);

		if (g_recentKeys.find(dedupKey) != g_recentKeys.end()) {
			LOG_INFO(
				"Scanner: ignored blocked file (already scanned) pid=%lu subtype=%lu path=%ls",
				Request.ProcessId,
				Request.OperationSubtype,
				RequestPathForLog(Request));
			return;
		}

		if (g_pendingKeys.find(dedupKey) != g_pendingKeys.end()) {
			LOG_INFO(
				"Scanner: ignored blocked file (already queued) pid=%lu subtype=%lu path=%ls",
				Request.ProcessId,
				Request.OperationSubtype,
				RequestPathForLog(Request));
			return;
		}

		g_pendingKeys.insert(dedupKey);
		g_queue.push(Request);
	}

	LOG_INFO(
		"Scanner: received blocked file pid=%lu subtype=%lu path=%ls",
		Request.ProcessId,
		Request.OperationSubtype,
		RequestPathForLog(Request));

	g_queueCv.notify_one();
}

}
