#include "FileIo.h"

#include <Windows.h>

#include <algorithm>
#include <cwchar>

namespace FileIo {

namespace {

std::wstring StripExtendedPathPrefix(const std::wstring& Path)
{
	if (Path.rfind(L"\\\\?\\", 0) == 0) {
		return Path.substr(4);
	}
	return Path;
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

	return L"";
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

bool ReadFileSample(const std::wstring& Win32Path, std::vector<unsigned char>& OutBuffer, size_t MaxBytes)
{
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

	const DWORD toRead = static_cast<DWORD>(std::min<size_t>(
		MaxBytes,
		static_cast<size_t>(fileSize.QuadPart > 0 ? fileSize.QuadPart : 0)));

	if (toRead == 0) {
		OutBuffer.clear();
		CloseHandle(file);
		return true;
	}

	OutBuffer.resize(toRead);
	DWORD bytesRead = 0;
	const BOOL readOk = ReadFile(file, OutBuffer.data(), toRead, &bytesRead, nullptr);
	CloseHandle(file);

	if (!readOk || bytesRead == 0) {
		return false;
	}

	OutBuffer.resize(bytesRead);
	return true;
}

}
