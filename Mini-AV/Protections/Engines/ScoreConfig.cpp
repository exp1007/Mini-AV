#include "ScoreConfig.h"

#include "../../Logging/Logging.h"

#include <Windows.h>
#include <ShlObj.h>

#include <cstdio>
#include <cstring>
#include <mutex>

#include "../../json.hpp"

namespace {

std::mutex g_mutex;
ScoreConfig::Thresholds g_thresholds;
std::vector<ScoreConfig::Combo> g_combos;
std::wstring g_configPath;
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

std::wstring BuildDefaultConfigPath()
{
	return BuildMiniAvFolder() + L"\\scoring.json";
}

bool EnsureMiniAvFolder()
{
	const std::wstring folder = BuildMiniAvFolder();
	const int result = SHCreateDirectoryExW(nullptr, folder.c_str(), nullptr);
	return result == ERROR_SUCCESS || result == ERROR_ALREADY_EXISTS;
}

std::vector<std::string> ParseStringArray(const nlohmann::json& Node, const char* Key)
{
	std::vector<std::string> out;
	if (!Node.contains(Key) || !Node[Key].is_array()) {
		return out;
	}
	for (const auto& entry : Node[Key]) {
		if (entry.is_string()) {
			const std::string value = entry.get<std::string>();
			if (!value.empty()) {
				out.push_back(value);
			}
		}
	}
	return out;
}

const char* DefaultConfigContent()
{
	// Default scoring model. "thresholds" sets the verdict bands; "combos" add a
	// bonus when several behaviors co-occur (worse than the plain sum). Each
	// "requires" entry is a signal-id prefix — "ad." matches any anti-debug
	// sub-signal, "cap.injection" matches that capability exactly. Edit live; the
	// file reloads on restart.
	return R"JSON({
  "thresholds": { "suspicious": 30, "dangerous": 50, "block": 60 },
  "combos": [
    {
      "id": "combo.injection_antidebug_c2",
      "name": "Process injection + anti-debug + network C2",
      "bonus": 25,
      "requires": ["cap.injection", "ad.", "cap.network"]
    },
    {
      "id": "combo.injection_dynamic_api",
      "name": "Injection via dynamically-resolved APIs",
      "bonus": 15,
      "requires": ["cap.injection", "cap.dynamic_api"]
    },
    {
      "id": "combo.ransom_antianalysis",
      "name": "Bulk crypto + anti-analysis",
      "bonus": 15,
      "requires": ["cap.ransom", "ad."]
    },
    {
      "id": "combo.packed_antidebug",
      "name": "Packed code + anti-debug",
      "bonus": 10,
      "requires": ["pe.packed", "ad."]
    },
    {
      "id": "combo.similarity_capability",
      "name": "Known-malware similarity + malicious capability",
      "bonus": 20,
      "requires": ["sim.", "cap."]
    }
  ]
}
)JSON";
}

bool WriteDefaultConfigFile(const std::wstring& Path)
{
	FILE* file = nullptr;
	if (_wfopen_s(&file, Path.c_str(), L"wb") != 0 || file == nullptr) {
		return false;
	}
	const char* content = DefaultConfigContent();
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
		LOG_ERROR("ScoreConfig: failed to parse JSON %ls", LogPath);
		return false;
	}

	if (doc.contains("thresholds") && doc["thresholds"].is_object()) {
		const auto& t = doc["thresholds"];
		g_thresholds.Suspicious = t.value("suspicious", g_thresholds.Suspicious);
		g_thresholds.Dangerous = t.value("dangerous", g_thresholds.Dangerous);
		g_thresholds.Block = t.value("block", g_thresholds.Block);
	}

	size_t added = 0;
	if (doc.contains("combos") && doc["combos"].is_array()) {
		for (const auto& entry : doc["combos"]) {
			if (!entry.is_object()) {
				continue;
			}
			ScoreConfig::Combo combo;
			combo.Id = entry.value("id", std::string());
			combo.Name = entry.value("name", combo.Id);
			combo.Bonus = entry.value("bonus", 0);
			combo.Requires = ParseStringArray(entry, "requires");

			if (combo.Id.empty() || combo.Bonus == 0 || combo.Requires.size() < 2) {
				LOG_WARNING("ScoreConfig: skipping invalid combo '%s'", combo.Id.c_str());
				continue;
			}
			g_combos.push_back(std::move(combo));
			++added;
		}
	}

	LOG_INFO(
		"ScoreConfig: thresholds(susp=%d,dang=%d,block=%d) combos=%zu from %ls",
		g_thresholds.Suspicious, g_thresholds.Dangerous, g_thresholds.Block, added, LogPath);
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

namespace ScoreConfig {

bool Initialize()
{
	std::lock_guard<std::mutex> lock(g_mutex);
	g_thresholds = Thresholds{};
	g_combos.clear();
	g_configPath = BuildDefaultConfigPath();
	g_initialized = true;

	EnsureMiniAvFolder();

	if (!LoadFromJsonFile(g_configPath)) {
		if (WriteDefaultConfigFile(g_configPath)) {
			LOG_INFO("ScoreConfig: created default %ls", g_configPath.c_str());
			LoadFromJsonFile(g_configPath);
		} else {
			LOG_WARNING("ScoreConfig: no config at %ls (using built-in defaults)", g_configPath.c_str());
		}
	}

	return true;
}

void Shutdown()
{
	std::lock_guard<std::mutex> lock(g_mutex);
	g_thresholds = Thresholds{};
	g_combos.clear();
	g_configPath.clear();
	g_initialized = false;
}

Thresholds GetThresholds()
{
	std::lock_guard<std::mutex> lock(g_mutex);
	return g_thresholds;
}

const std::vector<Combo>& Combos()
{
	return g_combos;
}

std::wstring ConfigPath()
{
	std::lock_guard<std::mutex> lock(g_mutex);
	return g_configPath;
}

}
