#include "Quarantine.h"

#include "../Logging/Logging.h"

#include <Windows.h>
#include <ShlObj.h>

#include <chrono>
#include <cwchar>
#include <mutex>
#include <string>

namespace {

std::mutex g_quarantineMutex;
std::wstring g_quarantineRoot;
bool g_initialized = false;

std::wstring BuildQuarantineRoot()
{
	WCHAR programData[MAX_PATH]{};
	const DWORD length = GetEnvironmentVariableW(L"ProgramData", programData, MAX_PATH);
	if (length == 0 || length >= MAX_PATH) {
		return L"C:\\ProgramData\\MiniAV\\Quarantine";
	}
	return std::wstring(programData) + L"\\MiniAV\\Quarantine";
}

bool PathStartsWithInsensitive(const std::wstring& Path, const std::wstring& Prefix)
{
	if (Prefix.empty() || Path.size() < Prefix.size()) {
		return false;
	}

	if (_wcsnicmp(Path.c_str(), Prefix.c_str(), Prefix.size()) != 0) {
		return false;
	}

	if (Path.size() == Prefix.size()) {
		return true;
	}

	const WCHAR next = Path[Prefix.size()];
	return next == L'\\' || next == L'/';
}

bool PathContainsInsensitive(const std::wstring& Path, const WCHAR* Segment)
{
	if (Segment == nullptr || Segment[0] == L'\0') {
		return false;
	}

	const size_t segmentLen = wcslen(Segment);
	for (size_t i = 0; i + segmentLen <= Path.size(); ++i) {
		if (_wcsnicmp(Path.c_str() + i, Segment, segmentLen) == 0) {
			return true;
		}
	}
	return false;
}

bool EnsureDirectoryTree(const std::wstring& Path)
{
	if (Path.empty()) {
		return false;
	}

	const int result = SHCreateDirectoryExW(nullptr, Path.c_str(), nullptr);
	if (result == ERROR_SUCCESS || result == ERROR_ALREADY_EXISTS) {
		return true;
	}

	LOG_ERROR("Quarantine: failed to create folder %ls err=%d", Path.c_str(), result);
	return false;
}

}

namespace Quarantine {

bool Initialize()
{
	std::lock_guard<std::mutex> lock(g_quarantineMutex);
	g_quarantineRoot = BuildQuarantineRoot();

	if (!EnsureDirectoryTree(g_quarantineRoot)) {
		return false;
	}

	g_initialized = true;
	LOG_INFO("Quarantine: folder %ls", g_quarantineRoot.c_str());
	return true;
}

void Shutdown()
{
	std::lock_guard<std::mutex> lock(g_quarantineMutex);
	g_initialized = false;
	g_quarantineRoot.clear();
}

bool IsQuarantinePath(const std::wstring& Path)
{
	std::lock_guard<std::mutex> lock(g_quarantineMutex);
	if (Path.empty()) {
		return false;
	}

	if (g_initialized && PathStartsWithInsensitive(Path, g_quarantineRoot)) {
		return true;
	}

	return PathContainsInsensitive(Path, L"\\ProgramData\\MiniAV\\Quarantine");
}

bool IsManagedPath(const std::wstring& Path)
{
	return IsQuarantinePath(Path);
}

bool MoveToQuarantine(const std::wstring& SourcePath, std::wstring& OutQuarantinePath)
{
	std::lock_guard<std::mutex> lock(g_quarantineMutex);
	if (!g_initialized || SourcePath.empty()) {
		return false;
	}

	if (PathStartsWithInsensitive(SourcePath, g_quarantineRoot)) {
		OutQuarantinePath = SourcePath;
		return true;
	}

	const DWORD sourceAttrs = GetFileAttributesW(SourcePath.c_str());
	if (sourceAttrs == INVALID_FILE_ATTRIBUTES) {
		const DWORD err = GetLastError();
		if (err == ERROR_FILE_NOT_FOUND) {
			return true;
		}
		LOG_ERROR("Quarantine: source unavailable %ls err=%lu", SourcePath.c_str(), err);
		return false;
	}

	const size_t slash = SourcePath.find_last_of(L"\\/");
	const std::wstring baseName = (slash != std::wstring::npos) ? SourcePath.substr(slash + 1) : SourcePath;

	const auto now = std::chrono::system_clock::now();
	const auto ticks = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

	WCHAR dest[MAX_PATH * 2]{};
	_snwprintf_s(
		dest,
		_TRUNCATE,
		L"%s\\%lld_%s",
		g_quarantineRoot.c_str(),
		static_cast<long long>(ticks),
		baseName.c_str());

	if (!MoveFileExW(SourcePath.c_str(), dest, MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING)) {
		const DWORD err = GetLastError();
		if (err == ERROR_FILE_NOT_FOUND) {
			return true;
		}
		LOG_ERROR("Quarantine: MoveFileEx failed src=%ls err=%lu", SourcePath.c_str(), err);
		return false;
	}

	OutQuarantinePath = dest;
	LOG_WARNING("Quarantine: moved %ls -> %ls", SourcePath.c_str(), dest);
	return true;
}

}
