#include "HashDatabase.h"

#include "../../Logging/Logging.h"

#include <Windows.h>
#include <ShlObj.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

#include "../../json.hpp"

namespace {

std::mutex g_mutex;
std::unordered_set<std::string> g_denyHashes;
std::wstring g_databasePath;
bool g_initialized = false;

std::wstring BuildMiniAvFolder()
{
	WCHAR programData[MAX_PATH]{};
	const DWORD length = GetEnvironmentVariableW(L"ProgramData", programData, MAX_PATH);
	if (length == 0 || length >= MAX_PATH) {
		return L"C:\\ProgramData\\MiniAV";
	}
	return std::wstring(programData) + L"\\MiniAV";
}

std::wstring BuildDefaultDatabasePath()
{
	return BuildMiniAvFolder() + L"\\hashes.json";
}

std::string NormalizeSha256Hex(std::string Value)
{
	Value.erase(
		std::remove_if(Value.begin(), Value.end(), [](unsigned char Ch) {
			return std::isspace(Ch) != 0;
		}),
		Value.end());

	if (Value.size() >= 2 && (Value[0] == '0' && (Value[1] == 'x' || Value[1] == 'X'))) {
		Value.erase(0, 2);
	}

	std::transform(Value.begin(), Value.end(), Value.begin(), [](unsigned char Ch) {
		return static_cast<char>(std::tolower(Ch));
	});

	if (Value.size() != 64) {
		return {};
	}

	for (char ch : Value) {
		if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) {
			return {};
		}
	}

	return Value;
}

bool EnsureMiniAvFolder()
{
	const std::wstring folder = BuildMiniAvFolder();
	const int result = SHCreateDirectoryExW(nullptr, folder.c_str(), nullptr);
	return result == ERROR_SUCCESS || result == ERROR_ALREADY_EXISTS;
}

bool WriteDefaultDatabaseFile(const std::wstring& Path)
{
	FILE* file = nullptr;
	if (_wfopen_s(&file, Path.c_str(), L"wb") != 0 || file == nullptr) {
		return false;
	}

	const char* content =
		"{\n"
		"  \"sha256_deny\": [\n"
		"  ]\n"
		"}\n";
	const size_t written = fwrite(content, 1, std::strlen(content), file);
	fclose(file);
	return written > 0;
}

bool LoadFromJsonContent(const std::string& Content, const wchar_t* LogPath)
{
	nlohmann::json doc;
	try {
		doc = nlohmann::json::parse(Content);
	} catch (...) {
		LOG_ERROR("HashDatabase: failed to parse JSON %ls", LogPath);
		return false;
	}

	if (!doc.contains("sha256_deny") || !doc["sha256_deny"].is_array()) {
		LOG_ERROR("HashDatabase: missing sha256_deny array in %ls", LogPath);
		return false;
	}

	size_t added = 0;
	for (const auto& entry : doc["sha256_deny"]) {
		if (!entry.is_string()) {
			continue;
		}
		const std::string normalized = NormalizeSha256Hex(entry.get<std::string>());
		if (!normalized.empty()) {
			g_denyHashes.insert(normalized);
			++added;
		}
	}

	LOG_INFO("HashDatabase: loaded %zu deny hashes from %ls", added, LogPath);
	return true;
}

bool LoadFromJsonFile(const std::wstring& Path)
{
	FILE* file = nullptr;
	if (_wfopen_s(&file, Path.c_str(), L"rb") != 0 || file == nullptr) {
		return false;
	}

	std::string content;
	char buffer[4096];
	size_t read = 0;
	while ((read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
		content.append(buffer, buffer + read);
	}
	fclose(file);

	if (content.empty()) {
		return false;
	}

	return LoadFromJsonContent(content, Path.c_str());
}

}

namespace HashDatabase {

bool Initialize()
{
	std::lock_guard<std::mutex> lock(g_mutex);
	g_denyHashes.clear();
	g_databasePath = BuildDefaultDatabasePath();
	g_initialized = true;

	EnsureMiniAvFolder();

	if (!LoadFromJsonFile(g_databasePath)) {
		if (WriteDefaultDatabaseFile(g_databasePath)) {
			LOG_INFO("HashDatabase: created default %ls", g_databasePath.c_str());
			LoadFromJsonFile(g_databasePath);
		} else {
			LOG_WARNING("HashDatabase: no database at %ls (deny list empty)", g_databasePath.c_str());
		}
	}

	LOG_INFO("HashDatabase: deny entries=%zu path=%ls", g_denyHashes.size(), g_databasePath.c_str());
	return true;
}

void Shutdown()
{
	std::lock_guard<std::mutex> lock(g_mutex);
	g_denyHashes.clear();
	g_databasePath.clear();
	g_initialized = false;
}

bool IsDenied(const std::string& Sha256HexLower)
{
	std::lock_guard<std::mutex> lock(g_mutex);
	if (!g_initialized || Sha256HexLower.empty()) {
		return false;
	}
	return g_denyHashes.find(Sha256HexLower) != g_denyHashes.end();
}

size_t DenyCount()
{
	std::lock_guard<std::mutex> lock(g_mutex);
	return g_denyHashes.size();
}

std::wstring DatabasePath()
{
	std::lock_guard<std::mutex> lock(g_mutex);
	return g_databasePath;
}

}
