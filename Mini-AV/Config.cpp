#include "Config.h"
#include "json.hpp"
#include <fstream>
#include "Logging/Logging.h"
#include "Protections/Engines/EngineSettings.h"

using json = nlohmann::json;

namespace Config {
    bool HasConfigFile() {
        std::ifstream file("settings.cfg");
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
        j["Engine"]["ApplyQuarantine"] = E.ApplyQuarantine;
        j["Engine"]["SensitivityPreset"] = static_cast<int>(E.Preset);
        j["Engine"]["Suspicious"] = E.Suspicious;
        j["Engine"]["Dangerous"] = E.Dangerous;
        j["Engine"]["Block"] = E.Block;

        std::ofstream file("settings.cfg");
        file << j.dump(4);
        file.close();
    }

    bool LoadConfig() {
        std::ifstream file("settings.cfg");
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