#include "PeImage.h"

#include <Windows.h>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <fstream>

namespace {

// Bounds-checked view: returns a pointer to `need` bytes at `offset`, or null if
// that range falls outside the buffer. Every dereference into a (hostile) PE goes
// through this so a malformed file can never read past the buffer.
const uint8_t* At(const std::vector<uint8_t>& Buffer, size_t Offset, size_t Need)
{
	if (Offset > Buffer.size() || Need > Buffer.size() - Offset) {
		return nullptr;
	}
	return Buffer.data() + Offset;
}

bool ReadFileCapped(const std::wstring& Path, std::vector<uint8_t>& Out, size_t MaxBytes)
{
	std::ifstream file(Path, std::ios::binary);
	if (!file) {
		return false;
	}

	file.seekg(0, std::ios::end);
	const std::streamoff size = file.tellg();
	if (size <= 0) {
		return false;
	}

	const size_t toRead = static_cast<size_t>(
		(std::min)(size, static_cast<std::streamoff>(MaxBytes)));
	Out.resize(toRead);
	file.seekg(0, std::ios::beg);
	file.read(reinterpret_cast<char*>(Out.data()), static_cast<std::streamsize>(toRead));
	Out.resize(static_cast<size_t>(file.gcount()));
	return !Out.empty();
}

double SectionEntropy(const std::vector<uint8_t>& Buffer, uint32_t RawOffset, uint32_t RawSize)
{
	const uint8_t* data = At(Buffer, RawOffset, RawSize);
	if (data == nullptr || RawSize == 0) {
		return 0.0;
	}

	size_t counts[256] = {};
	for (uint32_t i = 0; i < RawSize; ++i) {
		++counts[data[i]];
	}

	double entropy = 0.0;
	for (size_t value : counts) {
		if (value == 0) {
			continue;
		}
		const double p = static_cast<double>(value) / RawSize;
		entropy -= p * std::log2(p);
	}
	return entropy; // 0..8
}

// Map an RVA to a file offset using the section table. Returns false if the RVA
// falls outside every section's raw range.
bool RvaToOffset(const ScanEngine::PeInfo& Pe, uint32_t Rva, uint32_t& OutOffset)
{
	for (const auto& section : Pe.Sections) {
		const uint32_t span = (std::max)(section.VirtualSize, section.RawSize);
		if (Rva >= section.VirtualAddress && Rva < section.VirtualAddress + span) {
			const uint32_t delta = Rva - section.VirtualAddress;
			if (delta >= section.RawSize) {
				return false; // inside virtual padding, no backing bytes
			}
			OutOffset = section.RawOffset + delta;
			return true;
		}
	}
	return false;
}

std::string ToLower(std::string Value)
{
	std::transform(Value.begin(), Value.end(), Value.begin(), [](unsigned char ch) {
		return static_cast<char>(std::tolower(ch));
	});
	return Value;
}

// Read a NUL-terminated ASCII string starting at a file offset, bounded by the
// buffer end and a sane max length.
std::string ReadCString(const std::vector<uint8_t>& Buffer, uint32_t Offset, size_t MaxLen = 256)
{
	std::string out;
	for (size_t i = 0; i < MaxLen; ++i) {
		const uint8_t* p = At(Buffer, Offset + i, 1);
		if (p == nullptr || *p == 0) {
			break;
		}
		out.push_back(static_cast<char>(*p));
	}
	return out;
}

void ParseImports(ScanEngine::PeInfo& Pe, uint32_t ImportDirRva, uint32_t ImportDirSize)
{
	if (ImportDirRva == 0 || ImportDirSize == 0) {
		return;
	}

	uint32_t descOffset = 0;
	if (!RvaToOffset(Pe, ImportDirRva, descOffset)) {
		return;
	}

	constexpr size_t kImportDescriptorSize = sizeof(IMAGE_IMPORT_DESCRIPTOR); // 20
	constexpr size_t kMaxDlls = 1024;
	constexpr size_t kMaxFuncsPerDll = 8192;

	for (size_t dll = 0; dll < kMaxDlls; ++dll) {
		const uint8_t* raw = At(Pe.Buffer, descOffset + dll * kImportDescriptorSize, kImportDescriptorSize);
		if (raw == nullptr) {
			break;
		}

		IMAGE_IMPORT_DESCRIPTOR desc{};
		std::memcpy(&desc, raw, kImportDescriptorSize);

		// Terminating all-zero descriptor.
		if (desc.Name == 0 && desc.FirstThunk == 0 && desc.OriginalFirstThunk == 0) {
			break;
		}

		uint32_t nameOffset = 0;
		if (desc.Name != 0 && RvaToOffset(Pe, desc.Name, nameOffset)) {
			const std::string dllName = ReadCString(Pe.Buffer, nameOffset);
			if (!dllName.empty()) {
				Pe.ImportDlls.push_back(ToLower(dllName));
			}
		}

		// Prefer the Import Lookup Table (OriginalFirstThunk); fall back to IAT.
		const uint32_t thunkRva = desc.OriginalFirstThunk != 0 ? desc.OriginalFirstThunk : desc.FirstThunk;
		if (thunkRva == 0) {
			continue;
		}

		uint32_t thunkOffset = 0;
		if (!RvaToOffset(Pe, thunkRva, thunkOffset)) {
			continue;
		}

		const size_t thunkSize = Pe.Is64 ? sizeof(uint64_t) : sizeof(uint32_t);
		const uint64_t ordinalFlag = Pe.Is64 ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32;

		for (size_t i = 0; i < kMaxFuncsPerDll; ++i) {
			const uint8_t* tp = At(Pe.Buffer, thunkOffset + i * thunkSize, thunkSize);
			if (tp == nullptr) {
				break;
			}

			uint64_t value = 0;
			std::memcpy(&value, tp, thunkSize);
			if (value == 0) {
				break; // end of this DLL's thunk array
			}
			if (value & ordinalFlag) {
				continue; // imported by ordinal, no name
			}

			// Low 31 bits = RVA to IMAGE_IMPORT_BY_NAME { WORD Hint; char Name[]; }
			const uint32_t byNameRva = static_cast<uint32_t>(value & 0x7fffffff);
			uint32_t byNameOffset = 0;
			if (!RvaToOffset(Pe, byNameRva, byNameOffset)) {
				continue;
			}
			const std::string func = ReadCString(Pe.Buffer, byNameOffset + sizeof(WORD));
			if (!func.empty()) {
				Pe.Imports.push_back(ToLower(func));
			}
		}
	}
}

void ParsePe(ScanEngine::PeInfo& Pe)
{
	const uint8_t* dosRaw = At(Pe.Buffer, 0, sizeof(IMAGE_DOS_HEADER));
	if (dosRaw == nullptr) {
		return;
	}

	IMAGE_DOS_HEADER dos{};
	std::memcpy(&dos, dosRaw, sizeof(dos));
	if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
		return; // not even MZ -> not a PE, not malformed
	}

	// From here on it claims to be a PE; any failure is "malformed".
	Pe.Malformed = true;

	if (dos.e_lfanew <= 0) {
		return;
	}
	const uint32_t ntOffset = static_cast<uint32_t>(dos.e_lfanew);

	const uint8_t* sigRaw = At(Pe.Buffer, ntOffset, sizeof(DWORD));
	if (sigRaw == nullptr) {
		return;
	}
	DWORD signature = 0;
	std::memcpy(&signature, sigRaw, sizeof(signature));
	if (signature != IMAGE_NT_SIGNATURE) {
		return;
	}

	const uint32_t fileHeaderOffset = ntOffset + sizeof(DWORD);
	const uint8_t* fhRaw = At(Pe.Buffer, fileHeaderOffset, sizeof(IMAGE_FILE_HEADER));
	if (fhRaw == nullptr) {
		return;
	}
	IMAGE_FILE_HEADER fileHeader{};
	std::memcpy(&fileHeader, fhRaw, sizeof(fileHeader));

	const uint32_t optHeaderOffset = fileHeaderOffset + sizeof(IMAGE_FILE_HEADER);
	const uint16_t optMagicNeeded = sizeof(WORD);
	const uint8_t* magicRaw = At(Pe.Buffer, optHeaderOffset, optMagicNeeded);
	if (magicRaw == nullptr) {
		return;
	}
	WORD optMagic = 0;
	std::memcpy(&optMagic, magicRaw, sizeof(optMagic));

	uint32_t importDirRva = 0;
	uint32_t importDirSize = 0;

	if (optMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		Pe.Is64 = false;
		const uint8_t* ohRaw = At(Pe.Buffer, optHeaderOffset, sizeof(IMAGE_OPTIONAL_HEADER32));
		if (ohRaw == nullptr) {
			return;
		}
		IMAGE_OPTIONAL_HEADER32 oh{};
		std::memcpy(&oh, ohRaw, sizeof(oh));
		if (IMAGE_DIRECTORY_ENTRY_IMPORT < oh.NumberOfRvaAndSizes) {
			importDirRva = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
			importDirSize = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
		}
	} else if (optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		Pe.Is64 = true;
		const uint8_t* ohRaw = At(Pe.Buffer, optHeaderOffset, sizeof(IMAGE_OPTIONAL_HEADER64));
		if (ohRaw == nullptr) {
			return;
		}
		IMAGE_OPTIONAL_HEADER64 oh{};
		std::memcpy(&oh, ohRaw, sizeof(oh));
		if (IMAGE_DIRECTORY_ENTRY_IMPORT < oh.NumberOfRvaAndSizes) {
			importDirRva = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
			importDirSize = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
		}
	} else {
		return; // ROM image or unknown optional header
	}

	// Section table immediately follows the optional header.
	const uint32_t sectionTableOffset = optHeaderOffset + fileHeader.SizeOfOptionalHeader;
	const uint16_t sectionCount = fileHeader.NumberOfSections;
	if (sectionCount == 0 || sectionCount > 96) {
		return; // PE spec caps sections at 96
	}

	Pe.Sections.reserve(sectionCount);
	for (uint16_t i = 0; i < sectionCount; ++i) {
		const uint8_t* secRaw = At(
			Pe.Buffer,
			sectionTableOffset + static_cast<size_t>(i) * sizeof(IMAGE_SECTION_HEADER),
			sizeof(IMAGE_SECTION_HEADER));
		if (secRaw == nullptr) {
			return;
		}
		IMAGE_SECTION_HEADER sh{};
		std::memcpy(&sh, secRaw, sizeof(sh));

		ScanEngine::PeSection section;
		char name[9] = {};
		std::memcpy(name, sh.Name, 8);
		section.Name = name;
		section.VirtualAddress = sh.VirtualAddress;
		section.VirtualSize = sh.Misc.VirtualSize;
		section.RawOffset = sh.PointerToRawData;
		section.RawSize = sh.SizeOfRawData;
		section.Characteristics = sh.Characteristics;
		section.Executable =
			(sh.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 ||
			(sh.Characteristics & IMAGE_SCN_CNT_CODE) != 0;
		section.Entropy = SectionEntropy(Pe.Buffer, sh.PointerToRawData, sh.SizeOfRawData);
		Pe.Sections.push_back(std::move(section));
	}

	ParseImports(Pe, importDirRva, importDirSize);

	Pe.Valid = true;
	Pe.Malformed = false;
}

} // namespace

namespace {

constexpr size_t kMinStringRun = 4;

void AppendLoweredRun(std::string& Blob, const std::string& Run)
{
	for (char ch : Run) {
		Blob.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
	}
	Blob.push_back('\n');
}

// Extract printable runs (>= kMinStringRun chars) from the buffer into one
// lowercased blob, covering both ASCII and UTF-16LE (printable byte + 0x00).
std::string ExtractStrings(const std::vector<uint8_t>& Buffer)
{
	std::string blob;
	blob.reserve(Buffer.size() / 4 + 16);

	std::string current;
	for (uint8_t byte : Buffer) {
		if (byte >= 0x20 && byte <= 0x7e) {
			current.push_back(static_cast<char>(byte));
		} else {
			if (current.size() >= kMinStringRun) {
				AppendLoweredRun(blob, current);
			}
			current.clear();
		}
	}
	if (current.size() >= kMinStringRun) {
		AppendLoweredRun(blob, current);
	}

	current.clear();
	for (size_t i = 0; i + 1 < Buffer.size(); i += 2) {
		const uint8_t lo = Buffer[i];
		const uint8_t hi = Buffer[i + 1];
		if (hi == 0x00 && lo >= 0x20 && lo <= 0x7e) {
			current.push_back(static_cast<char>(lo));
		} else {
			if (current.size() >= kMinStringRun) {
				AppendLoweredRun(blob, current);
			}
			current.clear();
		}
	}
	if (current.size() >= kMinStringRun) {
		AppendLoweredRun(blob, current);
	}

	return blob;
}

} // namespace

namespace PeImage {

bool Parse(const std::wstring& Path, ScanEngine::PeInfo& Out, size_t MaxBytes)
{
	if (!ReadFileCapped(Path, Out.Buffer, MaxBytes)) {
		return false;
	}
	Out.Read = true;
	ParsePe(Out);
	return true;
}

const std::string& GetStrings(ScanEngine::PeInfo& Pe)
{
	if (!Pe.StringsExtracted) {
		Pe.StringBlob = ExtractStrings(Pe.Buffer);
		Pe.StringsExtracted = true;
	}
	return Pe.StringBlob;
}

} // namespace PeImage
