#include "TlshDatabase.h"

#include "../../Logging/Logging.h"
#include "TLSH/tlsh.h"

#include <Windows.h>
#include <ShlObj.h>

#include <climits>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include "../../json.hpp"

namespace {

struct TlshEntry {
	Tlsh Hash;                 // pre-parsed digest (valid by construction — invalid ones are dropped at load)
	std::string TlshStr;       // original digest string, kept so the file can be re-serialized
	std::string Name;
	std::string Family;
	int MaxDistance = -1;      // -1 => use the caller-supplied default
};

std::mutex g_mutex;
std::vector<TlshEntry> g_entries;
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
	return BuildMiniAvFolder() + L"\\tlsh.json";
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
		"  \"tlsh_deny\": [\n"
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
		LOG_ERROR("TlshDatabase: failed to parse JSON %ls", LogPath);
		return false;
	}

	if (!doc.contains("tlsh_deny") || !doc["tlsh_deny"].is_array()) {
		LOG_ERROR("TlshDatabase: missing tlsh_deny array in %ls", LogPath);
		return false;
	}

	size_t added = 0;
	size_t skipped = 0;
	for (const auto& entry : doc["tlsh_deny"]) {
		if (!entry.is_object()) {
			++skipped;
			continue;
		}

		const std::string tlshStr = entry.value("tlsh", std::string());
		if (tlshStr.empty()) {
			++skipped;
			continue;
		}

		TlshEntry parsed;
		// fromTlshStr returns 0 on success; reject anything that doesn't parse into a
		// usable digest so per-scan matching never touches an invalid object.
		if (parsed.Hash.fromTlshStr(tlshStr.c_str()) != 0 || !parsed.Hash.isValid()) {
			LOG_WARNING("TlshDatabase: skipping invalid TLSH digest '%s'", tlshStr.c_str());
			++skipped;
			continue;
		}

		parsed.TlshStr = tlshStr;
		parsed.Name = entry.value("name", std::string());
		parsed.Family = entry.value("family", std::string());
		parsed.MaxDistance = entry.value("max_distance", -1);

		g_entries.push_back(std::move(parsed));
		++added;
	}

	LOG_INFO("TlshDatabase: loaded %zu digests (%zu skipped) from %ls", added, skipped, LogPath);
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

// Re-serializes the current in-memory blacklist to tlsh.json. Caller holds g_mutex.
// Entries that failed to parse at load were already dropped, so this also prunes a
// bad file. Requires write access to %ProgramData%\MiniAV (the elevated service has it).
bool SaveToJson()
{
	nlohmann::json doc;
	doc["tlsh_deny"] = nlohmann::json::array();
	for (const TlshEntry& entry : g_entries) {
		nlohmann::json je;
		je["tlsh"] = entry.TlshStr;
		if (!entry.Name.empty())   je["name"] = entry.Name;
		if (!entry.Family.empty()) je["family"] = entry.Family;
		if (entry.MaxDistance >= 0) je["max_distance"] = entry.MaxDistance;
		doc["tlsh_deny"].push_back(std::move(je));
	}

	const std::string text = doc.dump(2);

	EnsureMiniAvFolder();

	FILE* file = nullptr;
	if (_wfopen_s(&file, g_databasePath.c_str(), L"wb") != 0 || file == nullptr) {
		LOG_ERROR("TlshDatabase: cannot write %ls", g_databasePath.c_str());
		return false;
	}
	const size_t written = fwrite(text.data(), 1, text.size(), file);
	fclose(file);
	return written == text.size();
}

}

namespace TlshDatabase {

bool Initialize()
{
	std::lock_guard<std::mutex> lock(g_mutex);
	g_entries.clear();
	g_databasePath = BuildDefaultDatabasePath();
	g_initialized = true;

	EnsureMiniAvFolder();

	if (!LoadFromJsonFile(g_databasePath)) {
		if (WriteDefaultDatabaseFile(g_databasePath)) {
			LOG_INFO("TlshDatabase: created default %ls", g_databasePath.c_str());
			LoadFromJsonFile(g_databasePath);
		} else {
			LOG_WARNING("TlshDatabase: no database at %ls (blacklist empty)", g_databasePath.c_str());
		}
	}

	LOG_INFO("TlshDatabase: entries=%zu path=%ls", g_entries.size(), g_databasePath.c_str());
	return true;
}

void Shutdown()
{
	std::lock_guard<std::mutex> lock(g_mutex);
	g_entries.clear();
	g_databasePath.clear();
	g_initialized = false;
}

MatchResult Match(const Tlsh& Candidate, int DefaultMaxDistance)
{
	std::lock_guard<std::mutex> lock(g_mutex);

	MatchResult best;
	if (!g_initialized || g_entries.empty()) {
		return best;
	}

	int bestDistance = INT_MAX;
	for (const TlshEntry& entry : g_entries) {
		const int limit = entry.MaxDistance >= 0 ? entry.MaxDistance : DefaultMaxDistance;
		const int distance = Candidate.totalDiff(&entry.Hash, true);
		if (distance <= limit && distance < bestDistance) {
			bestDistance = distance;
			best.Found = true;
			best.Distance = distance;
			best.Name = entry.Name;
			best.Family = entry.Family;
		}
	}

	return best;
}

bool AddEntry(const std::string& TlshStr, const std::string& Name, const std::string& Family, int MaxDistance)
{
	std::lock_guard<std::mutex> lock(g_mutex);
	if (!g_initialized) {
		return false;
	}

	TlshEntry entry;
	// Validate before committing: a bad digest must never enter the live set.
	if (entry.Hash.fromTlshStr(TlshStr.c_str()) != 0 || !entry.Hash.isValid()) {
		LOG_WARNING("TlshDatabase: rejected invalid TLSH '%s'", TlshStr.c_str());
		return false;
	}

	entry.TlshStr = TlshStr;
	entry.Name = Name;
	entry.Family = Family;
	entry.MaxDistance = MaxDistance;
	g_entries.push_back(std::move(entry));

	// Apply live (no restart) and persist. If the write fails the entry still works
	// for this session; the caller surfaces the save result.
	const bool saved = SaveToJson();
	LOG_INFO("TlshDatabase: added '%s' entries=%zu saved=%d", TlshStr.c_str(), g_entries.size(), saved ? 1 : 0);
	return saved;
}

size_t EntryCount()
{
	std::lock_guard<std::mutex> lock(g_mutex);
	return g_entries.size();
}

std::wstring DatabasePath()
{
	std::lock_guard<std::mutex> lock(g_mutex);
	return g_databasePath;
}

}
