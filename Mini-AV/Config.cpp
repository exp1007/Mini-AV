#include "Config.h"
#include "json.hpp"
#include <fstream>
#include "Logging/Logging.h"
#include "Protections/Engines/EngineSettings.h"

#include <Windows.h>
#include <ShlObj.h>
#include <string>

using json = nlohmann::json;

namespace {
    // settings.cfg lives alongside the other Mini-AV data files in
    // %ProgramData%\MiniAV\ (hashes.json, capabilities.json, scoring.json,
    // Quarantine\). Built the same way as Quarantine::BuildQuarantineRoot: a
    // missing/oversized ProgramData env var falls back to the canonical C: path.
    std::wstring ConfigDir() {
        WCHAR programData[MAX_PATH]{};
        const DWORD length = GetEnvironmentVariableW(L"ProgramData", programData, MAX_PATH);
        if (length == 0 || length >= MAX_PATH) {
            return L"C:\\ProgramData\\MiniAV";
        }
        return std::wstring(programData) + L"\\MiniAV";
    }

    std::wstring ConfigPath() {
        return ConfigDir() + L"\\settings.cfg";
    }
}

namespace Config {
    bool HasConfigFile() {
        std::ifstream file(ConfigPath().c_str());
        return file.good();
    }

    void SaveConfig() {
        json j;

        j["DebugWindow"] = Data.DebugWindow;
        j["DebugPanelWindow"] = Data.DebugPanelWindow;
        j["StylesWindow"] = Data.StylesWindow;
        j["ViewAlerts"] = Data.ViewAlerts;
        j["ViewLogs"] = Data.ViewLogs;
        j["ViewConsoleLogs"] = Data.ViewConsoleLogs;
        j["IsProtected"] = Data.IsProtected;
        j["ProtectedProc"] = Data.ProtectedProc.Name;
        j["ScanDelay"] = Globals::ScanDelay;

        const EngineSettings::Settings& E = EngineSettings::Current;
        j["Engine"]["RealtimeProtection"] = E.RealtimeProtection;
        j["Engine"]["UseHashDenyList"] = E.UseHashDenyList;
        j["Engine"]["UseContextEngine"] = E.UseContextEngine;
        j["Engine"]["UseCapabilityEngine"] = E.UseCapabilityEngine;
        j["Engine"]["UseAntiDebugEngine"] = E.UseAntiDebugEngine;
        j["Engine"]["UseTlshEngine"] = E.UseTlshEngine;
        j["Engine"]["TlshMaxDistance"] = E.TlshMaxDistance;
        j["Engine"]["ApplyQuarantine"] = E.ApplyQuarantine;
        j["Engine"]["SensitivityPreset"] = static_cast<int>(E.Preset);
        j["Engine"]["Suspicious"] = E.Suspicious;
        j["Engine"]["Dangerous"] = E.Dangerous;
        j["Engine"]["Block"] = E.Block;

        // Ensure %ProgramData%\MiniAV\ exists (config may be saved before the
        // engine's Initialize creates it). SHCreateDirectoryExW is a no-op if present.
        SHCreateDirectoryExW(nullptr, ConfigDir().c_str(), nullptr);

        std::ofstream file(ConfigPath().c_str());
        file << j.dump(4);
        file.close();
    }

    bool LoadConfig() {
        std::ifstream file(ConfigPath().c_str());
        if (!file.is_open())
            return false;
        json j;
        try {
            file >> j;
        } catch (...) {
            return false;
        }

        Data.DebugWindow = j.value("DebugWindow", Data.DebugWindow);
        Data.DebugPanelWindow = j.value("DebugPanelWindow", Data.DebugPanelWindow);
        Data.StylesWindow = j.value("StylesWindow", Data.StylesWindow);
        Data.ViewAlerts = j.value("ViewAlerts", Data.ViewAlerts);
        Data.ViewLogs = j.value("ViewLogs", Data.ViewLogs);
        Data.ViewConsoleLogs = j.value("ViewConsoleLogs", Data.ViewConsoleLogs);
        Data.IsProtected = j.value("IsProtected", Data.IsProtected);

        Data.ProtectedProc.Name = j.value("ProtectedProc", Data.ProtectedProc.Name);
        Globals::ScanDelay = j.value("ScanDelay", Globals::ScanDelay);

        if (j.contains("Engine") && j["Engine"].is_object()) {
            const json& je = j["Engine"];
            EngineSettings::Settings& E = EngineSettings::Current;
            E.RealtimeProtection = je.value("RealtimeProtection", E.RealtimeProtection);
            E.UseHashDenyList = je.value("UseHashDenyList", E.UseHashDenyList);
            E.UseContextEngine = je.value("UseContextEngine", E.UseContextEngine);
            E.UseCapabilityEngine = je.value("UseCapabilityEngine", E.UseCapabilityEngine);
            E.UseAntiDebugEngine = je.value("UseAntiDebugEngine", E.UseAntiDebugEngine);
            E.UseTlshEngine = je.value("UseTlshEngine", E.UseTlshEngine);
            E.TlshMaxDistance = je.value("TlshMaxDistance", E.TlshMaxDistance);
            E.ApplyQuarantine = je.value("ApplyQuarantine", E.ApplyQuarantine);
            E.Preset = static_cast<EngineSettings::Sensitivity>(
                je.value("SensitivityPreset", static_cast<int>(E.Preset)));
            E.Suspicious = je.value("Suspicious", E.Suspicious);
            E.Dangerous = je.value("Dangerous", E.Dangerous);
            E.Block = je.value("Block", E.Block);
        }

        file.close();

        if (Data.ViewConsoleLogs) {
            TerminalLogs::Initialize();
        } else {
            TerminalLogs::Shutdown();
        }

        return true;
    }
}