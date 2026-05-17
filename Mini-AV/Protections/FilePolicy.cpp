#include "FilePolicy.h"

#include "Engines/ScanEngine.h"
#include "FileIo.h"
#include "Quarantine.h"
#include "../Logging/Logging.h"

#include <cwchar>
#include <string>
#include <vector>

namespace {

constexpr const WCHAR kBlockTestExe[] = L"MiniAvBlockTest.exe";
constexpr const WCHAR kWindowsAppsSegment[] = L"\\Microsoft\\WindowsApps\\";
constexpr size_t kMaxReadBytes = 4096;

bool PathContainsInsensitive(const std::wstring& Path, const WCHAR* Needle)
{
	if (Needle == nullptr || Needle[0] == L'\0') {
		return false;
	}

	for (size_t i = 0; Path[i] != L'\0'; ++i) {
		if (_wcsnicmp(Path.c_str() + i, Needle, wcslen(Needle)) == 0) {
			return true;
		}
	}
	return false;
}

bool IsTestBlockFilename(const std::wstring& Path)
{
	if (Path.empty()) {
		return false;
	}

	const WCHAR* path = Path.c_str();
	const WCHAR* slash = wcsrchr(path, L'\\');
	const WCHAR* fname = slash ? (slash + 1) : path;
	const WCHAR* colon = wcschr(fname, L':');
	const size_t fnameLen = colon ? static_cast<size_t>(colon - fname) : wcslen(fname);
	const size_t blockLen = wcslen(kBlockTestExe);
	return fnameLen == blockLen && _wcsnicmp(fname, kBlockTestExe, blockLen) == 0;
}

bool HasExecutableExtension(const std::wstring& Path)
{
	const size_t dot = Path.find_last_of(L'.');
	if (dot == std::wstring::npos || dot + 1 >= Path.size()) {
		return false;
	}

	const std::wstring ext = Path.substr(dot);
	return _wcsicmp(ext.c_str(), L".exe") == 0 ||
		_wcsicmp(ext.c_str(), L".dll") == 0 ||
		_wcsicmp(ext.c_str(), L".sys") == 0;
}

std::wstring RequestNtPath(const MINIAV_CREATE_DECISION_REQUEST& Request)
{
	const size_t charCount = (Request.PathLengthChars > 0 && Request.PathLengthChars < MINIAV_MAX_PATH_CHARS)
		? Request.PathLengthChars
		: wcsnlen(Request.Path, MINIAV_MAX_PATH_CHARS);
	return std::wstring(Request.Path, charCount);
}

}

namespace FilePolicy {

bool ShouldEvaluateCreate(const MINIAV_CREATE_DECISION_REQUEST& Request)
{
	if (Request.Path[0] == L'\0') {
		return false;
	}

	const std::wstring ntPath = RequestNtPath(Request);
	const std::wstring win32Early = FileIo::NtPathToWin32(ntPath);
	if (Quarantine::IsQuarantinePath(ntPath) || Quarantine::IsQuarantinePath(win32Early)) {
		return true;
	}

	if (IsTestBlockFilename(ntPath) || IsTestBlockFilename(win32Early)) {
		return true;
	}

	if (Request.OperationSubtype != static_cast<unsigned long>(MiniAvOpExecuteOrImage)) {
		return false;
	}

	if (PathContainsInsensitive(ntPath, kWindowsAppsSegment)) {
		return false;
	}

	const std::wstring win32Path = FileIo::NtPathToWin32(ntPath);
	if (!win32Path.empty() && !HasExecutableExtension(win32Path)) {
		return false;
	}

	return true;
}

ExecutionScanResult EvaluateExecutionCreate(const MINIAV_CREATE_DECISION_REQUEST& Request)
{
	ExecutionScanResult result{};

	const std::wstring ntPath = RequestNtPath(Request);
	if (ntPath.empty()) {
		result.Verdict = ScanVerdict::Allow;
		result.Reason = "empty path";
		return result;
	}

	std::wstring win32Path = FileIo::NtPathToWin32(ntPath);
	if (win32Path.empty()) {
		result.Verdict = ScanVerdict::Error;
		result.Reason = "NT path conversion failed";
		LOG_ERROR("FilePolicy: %s for %ls", result.Reason.c_str(), ntPath.c_str());
		return result;
	}

	const std::wstring resolved = FileIo::ResolveFinalDosPath(win32Path);
	if (!resolved.empty()) {
		win32Path = resolved;
	}

	result.ResolvedPath = win32Path;

	if (Quarantine::IsQuarantinePath(ntPath) || Quarantine::IsQuarantinePath(win32Path)) {
		result.Verdict = ScanVerdict::Block;
		result.Reason = "quarantine access denied";
		result.ApplyQuarantine = false;
		LOG_WARNING("FilePolicy: deny quarantine access path=%ls", win32Path.c_str());
		return result;
	}

	if (IsTestBlockFilename(ntPath) || IsTestBlockFilename(win32Path)) {
		result.Verdict = ScanVerdict::Block;
		result.Reason = "test rule";
		LOG_WARNING("FilePolicy: block (test rule) path=%ls", win32Path.c_str());
		return result;
	}

	if (Request.OperationSubtype != static_cast<unsigned long>(MiniAvOpExecuteOrImage)) {
		result.Verdict = ScanVerdict::Allow;
		result.Reason = "not execute create";
		return result;
	}

	if (PathContainsInsensitive(ntPath, kWindowsAppsSegment) ||
		PathContainsInsensitive(win32Path, kWindowsAppsSegment)) {
		result.Verdict = ScanVerdict::Allow;
		result.Reason = "WindowsApps skip";
		return result;
	}

	if (!HasExecutableExtension(win32Path)) {
		result.Verdict = ScanVerdict::Allow;
		result.Reason = "non-executable extension";
		return result;
	}

	std::vector<unsigned char> sample;
	if (!FileIo::ReadFileSample(win32Path, sample, kMaxReadBytes)) {
		result.Verdict = ScanVerdict::Error;
		result.Reason = "file read failed";
		LOG_ERROR("FilePolicy: %s path=%ls", result.Reason.c_str(), win32Path.c_str());
		return result;
	}

	ScanEngine::ScanContext context{};
	context.ResolvedPath = win32Path;
	context.NtPath = ntPath;
	context.ProcessId = Request.ProcessId;
	context.OperationSubtype = Request.OperationSubtype;
	context.FileSample = std::move(sample);

	const ScanEngine::ScanVerdict engineVerdict = ScanEngine::RunPipeline(context);
	switch (engineVerdict) {
	case ScanEngine::ScanVerdict::Block:
		result.Verdict = ScanVerdict::Block;
		result.Reason = "engine block";
		break;
	case ScanEngine::ScanVerdict::Error:
		result.Verdict = ScanVerdict::Error;
		result.Reason = "engine error";
		break;
	case ScanEngine::ScanVerdict::Allow:
	default:
		result.Verdict = ScanVerdict::Allow;
		result.Reason = "engine allow";
		break;
	}

	if (result.Verdict != ScanVerdict::Allow) {
		LOG_INFO(
			"FilePolicy: verdict=%d path=%ls reason=%s",
			static_cast<int>(result.Verdict),
			win32Path.c_str(),
			result.Reason.c_str());
	}

	return result;
}

}
