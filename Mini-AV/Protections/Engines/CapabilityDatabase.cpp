#include "CapabilityDatabase.h"

#include "../../Logging/Logging.h"

#include <Windows.h>
#include <ShlObj.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include "../../json.hpp"

namespace {

std::mutex g_mutex;
std::vector<CapabilityDatabase::Capability> g_rules;
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
	return BuildMiniAvFolder() + L"\\capabilities.json";
}

bool EnsureMiniAvFolder()
{
	const std::wstring folder = BuildMiniAvFolder();
	const int result = SHCreateDirectoryExW(nullptr, folder.c_str(), nullptr);
	return result == ERROR_SUCCESS || result == ERROR_ALREADY_EXISTS;
}

std::string ToLower(std::string Value)
{
	std::transform(Value.begin(), Value.end(), Value.begin(), [](unsigned char ch) {
		return static_cast<char>(std::tolower(ch));
	});
	return Value;
}

ScanEngine::Confidence ParseConfidence(const std::string& Value)
{
	const std::string lowered = ToLower(Value);
	if (lowered == "high") {
		return ScanEngine::Confidence::High;
	}
	if (lowered == "medium" || lowered == "med") {
		return ScanEngine::Confidence::Medium;
	}
	return ScanEngine::Confidence::Low;
}

std::vector<std::string> ParseLowerArray(const nlohmann::json& Node, const char* Key)
{
	std::vector<std::string> out;
	if (!Node.contains(Key) || !Node[Key].is_array()) {
		return out;
	}
	for (const auto& entry : Node[Key]) {
		if (entry.is_string()) {
			const std::string value = ToLower(entry.get<std::string>());
			if (!value.empty()) {
				out.push_back(value);
			}
		}
	}
	return out;
}

const char* DefaultDatabaseContent()
{
	// Starter capability catalog. Imports are matched case-insensitively against
	// the PE import table; strings against extracted ASCII/UTF-16 runs. Edit this
	// file live (it reloads on restart) to add capabilities during a demo.
	return R"JSON({
  "capabilities": [
    {
      "id": "cap.injection",
      "name": "Process injection",
      "score": 40, "confidence": "high",
      "imports_all": ["virtualallocex", "writeprocessmemory"],
      "imports_any": ["createremotethread", "queueuserapc", "ntmapviewofsection", "rtlcreateuserthread"]
    },
    {
      "id": "cap.keylogger",
      "name": "Keylogging",
      "score": 30, "confidence": "medium",
      "imports_all": ["setwindowshookexa"],
      "imports_any": ["getasynckeystate", "getkeyboardstate"]
    },
    {
      "id": "cap.ransom",
      "name": "Ransomware / bulk crypto",
      "score": 35, "confidence": "high",
      "imports_any": ["cryptencrypt", "bcryptencrypt", "cryptacquirecontexta", "cryptacquirecontextw"],
      "strings_any": [".locked", ".encrypted", "your files have been encrypted", "readme_for_decrypt"]
    },
    {
      "id": "cap.persistence",
      "name": "Persistence (autorun)",
      "score": 25, "confidence": "medium",
      "imports_any": ["regsetvalueexa", "regsetvalueexw"],
      "strings_any": ["\\currentversion\\run", "appinit_dlls", "schtasks", "\\image file execution options"]
    },
    {
      "id": "cap.anti_vm",
      "name": "Anti-VM / sandbox evasion",
      "score": 20, "confidence": "medium",
      "strings_any": ["vbox", "vmware", "vmtoolsd", "sbiedll.dll", "qemu", "virtualbox"]
    },
    {
      "id": "cap.network",
      "name": "Network / C2",
      "score": 15, "confidence": "low",
      "imports_any": ["winhttpopen", "internetopena", "internetopenw", "internetopenurla", "wsastartup", "connect"]
    },
    {
      "id": "cap.cred_theft",
      "name": "Credential theft",
      "score": 30, "confidence": "high",
      "strings_any": ["vaultcli.dll", "\\login data", "\\mozilla\\firefox", "lsass", "wallet.dat"]
    },
    {
      "id": "cap.dynamic_api",
      "name": "Dynamic API resolution (evasion)",
      "score": 15, "confidence": "low",
      "imports_all": ["getprocaddress"],
      "imports_any": ["loadlibrarya", "loadlibraryw", "ldrloaddll"]
    },
    {
      "id": "cap.self_delete",
      "name": "Self-deletion",
      "score": 20, "confidence": "medium",
      "strings_any": ["cmd /c del", "cmd.exe /c del", "ping -n", "& del "]
    }
  ]
}
)JSON";
}

bool WriteDefaultDatabaseFile(const std::wstring& Path)
{
	FILE* file = nullptr;
	if (_wfopen_s(&file, Path.c_str(), L"wb") != 0 || file == nullptr) {
		return false;
	}
	const char* content = DefaultDatabaseContent();
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
		LOG_ERROR("CapabilityDatabase: failed to parse JSON %ls", LogPath);
		return false;
	}

	if (!doc.contains("capabilities") || !doc["capabilities"].is_array()) {
		LOG_ERROR("CapabilityDatabase: missing capabilities array in %ls", LogPath);
		return false;
	}

	size_t added = 0;
	for (const auto& entry : doc["capabilities"]) {
		if (!entry.is_object()) {
			continue;
		}

		CapabilityDatabase::Capability rule;
		rule.Id = entry.value("id", std::string());
		rule.Name = entry.value("name", rule.Id);
		rule.Score = entry.value("score", 0);
		rule.Conf = ParseConfidence(entry.value("confidence", std::string("low")));
		rule.ImportsAll = ParseLowerArray(entry, "imports_all");
		rule.ImportsAny = ParseLowerArray(entry, "imports_any");
		rule.StringsAny = ParseLowerArray(entry, "strings_any");

		const bool hasClause =
			!rule.ImportsAll.empty() || !rule.ImportsAny.empty() || !rule.StringsAny.empty();
		if (rule.Id.empty() || rule.Score == 0 || !hasClause) {
			LOG_WARNING("CapabilityDatabase: skipping invalid rule '%s'", rule.Id.c_str());
			continue;
		}

		g_rules.push_back(std::move(rule));
		++added;
	}

	LOG_INFO("CapabilityDatabase: loaded %zu capability rules from %ls", added, LogPath);
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

namespace CapabilityDatabase {

bool Initialize()
{
	std::lock_guard<std::mutex> lock(g_mutex);
	g_rules.clear();
	g_databasePath = BuildDefaultDatabasePath();
	g_initialized = true;

	EnsureMiniAvFolder();

	if (!LoadFromJsonFile(g_databasePath)) {
		if (WriteDefaultDatabaseFile(g_databasePath)) {
			LOG_INFO("CapabilityDatabase: created default %ls", g_databasePath.c_str());
			LoadFromJsonFile(g_databasePath);
		} else {
			LOG_WARNING("CapabilityDatabase: no database at %ls (no rules)", g_databasePath.c_str());
		}
	}

	LOG_INFO("CapabilityDatabase: rules=%zu path=%ls", g_rules.size(), g_databasePath.c_str());
	return true;
}

void Shutdown()
{
	std::lock_guard<std::mutex> lock(g_mutex);
	g_rules.clear();
	g_databasePath.clear();
	g_initialized = false;
}

const std::vector<Capability>& Rules()
{
	return g_rules;
}

size_t RuleCount()
{
	std::lock_guard<std::mutex> lock(g_mutex);
	return g_rules.size();
}

std::wstring DatabasePath()
{
	std::lock_guard<std::mutex> lock(g_mutex);
	return g_databasePath;
}

}
