#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ScanEngine {

struct PeSection {
	std::string Name;
	uint32_t VirtualAddress = 0;
	uint32_t VirtualSize = 0;
	uint32_t RawOffset = 0;
	uint32_t RawSize = 0;
	uint32_t Characteristics = 0;
	bool Executable = false;
	double Entropy = 0.0; // Shannon entropy of the raw section bytes, 0..8
};

// Parsed PE plus the raw file buffer. Collectors share this via ScanContext.Pe
// so the file is read and parsed exactly once per scan. Forward-declared in
// ScanEngine.h; defined here.
struct PeInfo {
	bool Read = false;       // file buffer was loaded
	bool Valid = false;      // a well-formed PE header was parsed
	bool Malformed = false;  // looked like a PE (MZ) but parsing failed bounds checks
	bool Is64 = false;       // PE32+ (x64) vs PE32 (x86)

	std::vector<uint8_t> Buffer;        // raw file bytes (capped at MaxBytes)
	std::vector<PeSection> Sections;
	std::vector<std::string> Imports;   // lowercased imported function names
	std::vector<std::string> ImportDlls; // lowercased imported module names

	// Lazily-built, lowercased blob of extracted ASCII/UTF-16 string runs,
	// separated by '\n'. Computed once on first GetStrings() call and shared by
	// every string-based collector. Empty string is a valid (no-strings) cache.
	std::string StringBlob;
	bool StringsExtracted = false;
};

} // namespace ScanEngine

namespace PeImage {

// Reads the file at Path (capped at MaxBytes) and parses its PE structure into
// Out. Always sets Out.Read on a successful read; sets Out.Valid only when a
// well-formed PE was parsed, Out.Malformed when an MZ file failed validation.
// Returns Out.Read.
bool Parse(const std::wstring& Path, ScanEngine::PeInfo& Out, size_t MaxBytes);

// Returns the lowercased extracted-strings blob for the parsed image, computing
// and caching it in Pe.StringBlob on first call. Cheap on subsequent calls.
const std::string& GetStrings(ScanEngine::PeInfo& Pe);

} // namespace PeImage
