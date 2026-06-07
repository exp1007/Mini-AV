#include "FileIo.h"

#include <Windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <cwchar>
#include <cstdio>
#include <string>
#include <vector>

namespace FileIo {

namespace {

std::wstring StripExtendedPathPrefix(const std::wstring& Path)
{
	// UNC long-path form: \\?\UNC\server\share\... -> \\server\share\...
	if (Path.rfind(L"\\\\?\\UNC\\", 0) == 0) {
		return L"\\\\" + Path.substr(8);
	}
	if (Path.rfind(L"\\\\?\\", 0) == 0) {
		return Path.substr(4);
	}
	return Path;
}

// Converts a network-redirector NT path to a UNC \\server\share\... path.
// Handles \Device\Mup\... and \Device\LanmanRedirector\..., including the
// optional ";X:0000000000000000\" drive-binding token that mapped network
// drives carry. Returns "" if NtPath is not a recognized network path.
std::wstring NetworkNtPathToUnc(const std::wstring& NtPath)
{
	static const wchar_t* const kPrefixes[] = {
		L"\\Device\\Mup\\",
		L"\\Device\\LanmanRedirector\\",
	};

	for (const wchar_t* prefix : kPrefixes) {
		const size_t prefixLen = wcslen(prefix);
		if (NtPath.size() <= prefixLen || _wcsnicmp(NtPath.c_str(), prefix, prefixLen) != 0) {
			continue;
		}

		std::wstring rest = NtPath.substr(prefixLen);
		// Skip a leading drive-binding token like ";Z:0000000000000000\".
		if (!rest.empty() && rest[0] == L';') {
			const size_t slash = rest.find(L'\\');
			if (slash == std::wstring::npos) {
				return L"";
			}
			rest = rest.substr(slash + 1);
		}

		if (rest.empty()) {
			return L"";
		}
		return L"\\\\" + rest;
	}

	return L"";
}

constexpr size_t kSha256DigestBytes = 32;
constexpr DWORD kHashReadChunkBytes = 1024u * 1024u;

std::string BytesToHexLower(const unsigned char* Data, size_t Length)
{
	static const char kHex[] = "0123456789abcdef";
	std::string out;
	out.resize(Length * 2);
	for (size_t i = 0; i < Length; ++i) {
		out[i * 2] = static_cast<char>(kHex[(Data[i] >> 4) & 0x0F]);
		out[i * 2 + 1] = static_cast<char>(kHex[Data[i] & 0x0F]);
	}
	return out;
}

}

std::wstring NtPathToWin32(const std::wstring& NtPath)
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

	// No drive-letter device matched. Network-redirector paths (e.g. VMware
	// shared folders under \Device\Mup\, mapped/unmapped UNC) have no drive
	// letter; map them to a \\server\share\... UNC path instead of failing
	// (which would fail-closed DENY every launch from a network share).
	return NetworkNtPathToUnc(NtPath);
}

std::wstring ResolveFinalDosPath(const std::wstring& Win32Path)
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

bool HashFileSha256(const std::wstring& Win32Path, std::string& OutHexLower, size_t MaxBytes)
{
	OutHexLower.clear();

	if (Win32Path.empty() || MaxBytes == 0) {
		return false;
	}

	HANDLE file = CreateFileW(
		Win32Path.c_str(),
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr);

	if (file == INVALID_HANDLE_VALUE) {
		return false;
	}

	LARGE_INTEGER fileSize{};
	if (!GetFileSizeEx(file, &fileSize)) {
		CloseHandle(file);
		return false;
	}

	if (fileSize.QuadPart < 0 || static_cast<unsigned long long>(fileSize.QuadPart) > MaxBytes) {
		CloseHandle(file);
		return false;
	}

	BCRYPT_ALG_HANDLE algorithm = nullptr;
	NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
	if (status != 0) {
		CloseHandle(file);
		return false;
	}

	BCRYPT_HASH_HANDLE hash = nullptr;
	DWORD hashObjectSize = 0;
	DWORD hashDataSize = 0;
	DWORD bytesReturned = 0;

	status = BCryptGetProperty(
		algorithm,
		BCRYPT_OBJECT_LENGTH,
		reinterpret_cast<PUCHAR>(&hashObjectSize),
		sizeof(hashObjectSize),
		&bytesReturned,
		0);
	if (status != 0) {
		BCryptCloseAlgorithmProvider(algorithm, 0);
		CloseHandle(file);
		return false;
	}

	std::vector<unsigned char> hashObject(hashObjectSize);
	status = BCryptCreateHash(
		algorithm,
		&hash,
		hashObject.data(),
		hashObjectSize,
		nullptr,
		0,
		0);
	if (status != 0) {
		BCryptCloseAlgorithmProvider(algorithm, 0);
		CloseHandle(file);
		return false;
	}

	std::vector<unsigned char> chunk(kHashReadChunkBytes);
	ULONGLONG remaining = static_cast<ULONGLONG>(fileSize.QuadPart);

	while (remaining > 0) {
		const DWORD request = static_cast<DWORD>(std::min<ULONGLONG>(remaining, kHashReadChunkBytes));
		DWORD bytesRead = 0;
		if (!ReadFile(file, chunk.data(), request, &bytesRead, nullptr) || bytesRead == 0) {
			BCryptDestroyHash(hash);
			BCryptCloseAlgorithmProvider(algorithm, 0);
			CloseHandle(file);
			return false;
		}

		status = BCryptHashData(hash, chunk.data(), bytesRead, 0);
		if (status != 0) {
			BCryptDestroyHash(hash);
			BCryptCloseAlgorithmProvider(algorithm, 0);
			CloseHandle(file);
			return false;
		}

		remaining -= bytesRead;
	}

	CloseHandle(file);

	unsigned char digest[kSha256DigestBytes]{};
	status = BCryptFinishHash(hash, digest, kSha256DigestBytes, 0);
	BCryptDestroyHash(hash);
	BCryptCloseAlgorithmProvider(algorithm, 0);

	if (status != 0) {
		return false;
	}

	OutHexLower = BytesToHexLower(digest, kSha256DigestBytes);
	return true;
}

}
