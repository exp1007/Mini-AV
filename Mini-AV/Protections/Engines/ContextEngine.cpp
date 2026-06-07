#include "ContextEngine.h"

#include "PeImage.h"
#include "../../Logging/Logging.h"

#include <Windows.h>

#include <algorithm>
#include <string>

namespace {

// Signal weights. None blocks on its own (block threshold is 60); the deceptive
// double-extension is the heaviest single context signal. Tunable later (Phase 3).
constexpr int kScoreMotw = 10;
constexpr int kScoreDoubleExt = 35;
constexpr int kScoreBadPath = 10;
constexpr int kScorePacked = 20;
constexpr int kScoreMalformed = 15;

// An executable section above this Shannon entropy reads as packed/encrypted.
constexpr double kPackedEntropyThreshold = 7.2;

std::wstring ToLowerW(std::wstring Value)
{
	std::transform(Value.begin(), Value.end(), Value.begin(), [](wchar_t ch) {
		return static_cast<wchar_t>(::towlower(ch));
	});
	return Value;
}

bool ContainsW(const std::wstring& Haystack, const wchar_t* Needle)
{
	return Haystack.find(Needle) != std::wstring::npos;
}

// Reads the Zone.Identifier alternate data stream and returns true if the file
// carries a ZoneId of 3 (Internet) or 4 (Untrusted) -> downloaded.
bool HasMarkOfTheWeb(const std::wstring& Path)
{
	const std::wstring stream = Path + L":Zone.Identifier";
	HANDLE handle = CreateFileW(
		stream.c_str(),
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr);
	if (handle == INVALID_HANDLE_VALUE) {
		return false; // no ADS -> not marked
	}

	char buffer[1024] = {};
	DWORD read = 0;
	const BOOL ok = ReadFile(handle, buffer, sizeof(buffer) - 1, &read, nullptr);
	CloseHandle(handle);
	if (!ok || read == 0) {
		return false;
	}

	std::string content(buffer, read);
	std::transform(content.begin(), content.end(), content.begin(), [](unsigned char ch) {
		return static_cast<char>(std::tolower(ch));
	});
	const size_t pos = content.find("zoneid=");
	if (pos == std::string::npos) {
		return false;
	}
	const size_t valuePos = pos + 7;
	if (valuePos >= content.size()) {
		return false;
	}
	const char zone = content[valuePos];
	return zone == '3' || zone == '4';
}

// True if the filename carries a document/image-looking extension immediately
// before its final executable extension, e.g. "invoice.pdf.exe". This is the
// reachable form of disguise: a plain ".pdf" never reaches the scanner because
// FilePolicy filters non-executable extensions before the pipeline runs.
bool HasDeceptiveDoubleExtension(const std::wstring& Path)
{
	const size_t slash = Path.find_last_of(L"\\/");
	const std::wstring name = ToLowerW(slash == std::wstring::npos ? Path : Path.substr(slash + 1));

	const size_t lastDot = name.find_last_of(L'.');
	if (lastDot == std::wstring::npos || lastDot == 0) {
		return false;
	}
	const size_t prevDot = name.find_last_of(L'.', lastDot - 1);
	if (prevDot == std::wstring::npos) {
		return false; // only one extension
	}

	const std::wstring middle = name.substr(prevDot + 1, lastDot - prevDot - 1);
	static const wchar_t* kLureExtensions[] = {
		L"pdf", L"doc", L"docx", L"xls", L"xlsx", L"ppt", L"pptx", L"txt", L"rtf",
		L"jpg", L"jpeg", L"png", L"gif", L"bmp", L"mp3", L"mp4", L"avi", L"zip",
	};
	for (const wchar_t* lure : kLureExtensions) {
		if (middle == lure) {
			return true;
		}
	}
	return false;
}

bool RunsFromRiskyLocation(const std::wstring& Path)
{
	const std::wstring lower = ToLowerW(Path);
	if (ContainsW(lower, L"\\temp\\") ||
		ContainsW(lower, L"\\downloads\\") ||
		ContainsW(lower, L"\\appdata\\")) {
		return true;
	}

	// Removable / network drive (e.g. USB stick).
	if (lower.size() >= 3 && lower[1] == L':' && lower[2] == L'\\') {
		const std::wstring root = lower.substr(0, 3);
		const UINT type = GetDriveTypeW(root.c_str());
		if (type == DRIVE_REMOVABLE || type == DRIVE_REMOTE) {
			return true;
		}
	}
	return false;
}

} // namespace

namespace ContextEngine {

void Collect(ScanEngine::ScanContext& Context)
{
	if (HasMarkOfTheWeb(Context.ResolvedPath)) {
		Context.AddSignal(
			"ctx.motw",
			"Downloaded from the internet (Mark-of-the-Web)",
			kScoreMotw,
			ScanEngine::Confidence::Low);
	}

	if (HasDeceptiveDoubleExtension(Context.ResolvedPath)) {
		Context.AddSignal(
			"ctx.double_ext",
			"Deceptive double extension (disguised executable)",
			kScoreDoubleExt,
			ScanEngine::Confidence::High);
	}

	if (RunsFromRiskyLocation(Context.ResolvedPath)) {
		Context.AddSignal(
			"ctx.bad_path",
			"Runs from a risky location (Temp/Downloads/AppData/removable)",
			kScoreBadPath,
			ScanEngine::Confidence::Low);
	}

	const ScanEngine::PeInfo* pe = Context.Pe;
	if (pe == nullptr) {
		return;
	}

	if (pe->Malformed) {
		Context.AddSignal(
			"pe.malformed",
			"Malformed PE header (failed validation)",
			kScoreMalformed,
			ScanEngine::Confidence::Medium);
		return; // section data is untrustworthy if parsing failed
	}

	if (pe->Valid) {
		for (const auto& section : pe->Sections) {
			if (section.Executable && section.Entropy > kPackedEntropyThreshold) {
				char detail[160];
				_snprintf_s(
					detail,
					sizeof(detail),
					_TRUNCATE,
					"Packed/encrypted code (section %s entropy %.2f)",
					section.Name.empty() ? "?" : section.Name.c_str(),
					section.Entropy);
				Context.AddSignal(
					"pe.packed",
					detail,
					kScorePacked,
					ScanEngine::Confidence::Medium);
				break; // one packed signal is enough
			}
		}
	}
}

}
