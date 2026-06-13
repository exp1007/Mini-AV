#include "FilePolicy.h"

#include "Engines/ScanEngine.h"
#include "Engines/EngineSettings.h"
#include "FileIo.h"
#include "Quarantine.h"
#include "../Logging/Logging.h"

#include <Windows.h>

#include <cwchar>
#include <string>
#include <vector>

namespace {

constexpr const WCHAR kBlockTestExe[] = L"MiniAvBlockTest.exe";
constexpr const WCHAR kWindowsAppsSegment[] = L"\\Microsoft\\WindowsApps\\";

// Trusted directories — anything under these is always allowed (skipped before
// the scan engine runs). They hold Windows-owned / installed, signed binaries
// that load constantly; scanning them is wasted work and (with fail-closed on
// errors) a needless risk to system stability. Matched as a case-insensitive
// substring so both NT paths (\Device\HarddiskVolumeN\Windows\...) and Win32
// paths (C:\Windows\...) are covered.
// Caveat: substring matching also accepts any directory literally named the same
// (e.g. C:\App\Windows\) — an accepted trade-off for the simpler, broader rule.
constexpr const WCHAR* kAllowedPathSegments[] = {
	L"\\Windows\\",                 // OS binaries (System32, SysWOW64, WinSxS, ...)
	L"\\Program Files\\",           // installed 64-bit software
	L"\\Program Files (x86)\\",     // installed 32-bit software
	L"\\ProgramData\\Microsoft\\Windows Defender\\", // bundled AV components
};

// Trusted file names — always allowed regardless of location. Kept deliberately
// short: matching by name alone is a known weakness (malware can adopt these
// names), so only ubiquitous, false-positive-prone OS processes belong here.
// Most real system binaries already live under the trusted directories above;
// this list only helps when one is launched from an unusual location.
constexpr const WCHAR* kAllowedFileNames[] = {
	L"explorer.exe",
	L"svchost.exe",
	L"services.exe",
	L"lsass.exe",
	L"csrss.exe",
	L"wininit.exe",
	L"winlogon.exe",
	L"smss.exe",
	L"taskhostw.exe",
	L"runtimebroker.exe",
	L"dllhost.exe",
	L"conhost.exe",
	L"fontdrvhost.exe",
	L"dwm.exe",
};

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

// Returns the file-name portion of a path (after the last backslash), stopping
// at an ADS ':' if present.
std::wstring FileNameOf(const std::wstring& Path)
{
	const WCHAR* path = Path.c_str();
	const WCHAR* slash = wcsrchr(path, L'\\');
	const WCHAR* name = slash ? (slash + 1) : path;
	const WCHAR* colon = wcschr(name, L':');
	const size_t len = colon ? static_cast<size_t>(colon - name) : wcslen(name);
	return std::wstring(name, len);
}

// Our own executable's file name, resolved once from the running module. A security
// product must never quarantine itself: Mini-AV.exe embeds every detection string it
// looks for (tool names like 'ollydbg', the self-delete / cred-theft / anti-VM rule
// literals, ...), so scanning its own image makes those capability rules fire and it
// self-detects. Matching by name carries the same accepted weakness as kAllowedFileNames
// (malware could adopt the name), which is fine for this POC.
const std::wstring& OwnExecutableName()
{
	static const std::wstring name = []() -> std::wstring {
		WCHAR buffer[MAX_PATH] = {};
		const DWORD len = GetModuleFileNameW(nullptr, buffer, MAX_PATH);
		if (len == 0 || len >= MAX_PATH) {
			return std::wstring();
		}
		return FileNameOf(std::wstring(buffer, len));
	}();
	return name;
}

// True when the path is in a trusted directory, has a trusted file name, or is our
// own executable, and so should bypass scanning entirely.
bool IsAlwaysAllowed(const std::wstring& Path)
{
	if (Path.empty()) {
		return false;
	}

	for (const WCHAR* segment : kAllowedPathSegments) {
		if (PathContainsInsensitive(Path, segment)) {
			return true;
		}
	}

	const std::wstring name = FileNameOf(Path);
	for (const WCHAR* allowed : kAllowedFileNames) {
		if (_wcsicmp(name.c_str(), allowed) == 0) {
			return true;
		}
	}

	const std::wstring& self = OwnExecutableName();
	if (!self.empty() && _wcsicmp(name.c_str(), self.c_str()) == 0) {
		return true;
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

	if (IsAlwaysAllowed(ntPath) || IsAlwaysAllowed(win32Early)) {
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
		result.Category = "Scan error";
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
		result.Category = "Quarantine access";
		result.ApplyQuarantine = false;
		LOG_WARNING("FilePolicy: deny quarantine access path=%ls", win32Path.c_str());
		return result;
	}

	if (IsTestBlockFilename(ntPath) || IsTestBlockFilename(win32Path)) {
		result.Verdict = ScanVerdict::Block;
		result.Reason = "test rule";
		result.Category = "Test rule";
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

	if (IsAlwaysAllowed(ntPath) || IsAlwaysAllowed(win32Path)) {
		result.Verdict = ScanVerdict::Allow;
		result.Reason = "allowlist skip";
		return result;
	}

	if (!HasExecutableExtension(win32Path)) {
		result.Verdict = ScanVerdict::Allow;
		result.Reason = "non-executable extension";
		return result;
	}

	ScanEngine::ScanContext context{};
	context.ResolvedPath = win32Path;
	context.NtPath = ntPath;
	context.ProcessId = Request.ProcessId;
	context.OperationSubtype = Request.OperationSubtype;

	const ScanEngine::PipelineResult pipeline = ScanEngine::RunPipeline(context);
	result.Score = pipeline.Score;
	result.Suspicious = pipeline.Suspicious;
	result.Dangerous = pipeline.Dangerous;
	result.Category = pipeline.Category;
	switch (pipeline.Verdict) {
	case ScanEngine::ScanVerdict::Block:
		result.Verdict = ScanVerdict::Block;
		result.Reason = pipeline.Reason.empty() ? "engine block" : pipeline.Reason;
		// Quarantine action is user-configurable: move the file, or deny only.
		result.ApplyQuarantine = EngineSettings::Current.ApplyQuarantine;
		break;
	case ScanEngine::ScanVerdict::Error:
		result.Verdict = ScanVerdict::Error;
		result.Reason = pipeline.Reason.empty() ? "engine error" : pipeline.Reason;
		break;
	case ScanEngine::ScanVerdict::Allow:
	default:
		result.Verdict = ScanVerdict::Allow;
		result.Reason = pipeline.Reason.empty() ? "engine allow" : pipeline.Reason;
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
