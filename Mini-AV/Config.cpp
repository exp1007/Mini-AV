#include "Config.h"
#include "json.hpp"
#include <fstream>
#include "Logging/Logging.h"

using json = nlohmann::json;

namespace Config {
    void SaveConfig() {
        json j;

        j["DebugWindow"] = Data.DebugWindow;
        j["StylesWindow"] = Data.StylesWindow;
        j["ViewAlerts"] = Data.ViewAlerts;
        j["ViewLogs"] = Data.ViewLogs;
        j["ViewConsoleLogs"] = Data.ViewConsoleLogs;
        j["IsProtected"] = Data.IsProtected;
        j["ProtectedProc"] = Data.ProtectedProc.Name;

        std::ofstream file("settings.cfg");
        file << j.dump(4);
        file.close();
    }

    void LoadConfig() {
        std::ifstream file("settings.cfg");
        if (!file.is_open()) return;
        json j;
        file >> j;

        Data.DebugWindow = j.value("DebugWindow", Data.DebugWindow);
        Data.StylesWindow = j.value("StylesWindow", Data.StylesWindow);
        Data.ViewAlerts = j.value("ViewAlerts", Data.ViewAlerts);
        Data.ViewLogs = j.value("ViewLogs", Data.ViewLogs);
        Data.ViewConsoleLogs = j.value("ViewConsoleLogs", Data.ViewConsoleLogs);
        Data.IsProtected = j.value("IsProtected", Data.IsProtected);

        Data.ProtectedProc.Name = j.value("ProtectedProc", Data.ProtectedProc.Name);

        file.close();

        if (Data.ViewConsoleLogs) {
            TerminalLogs::Initialize();
        } else {
            TerminalLogs::Shutdown();
        }
    }
}