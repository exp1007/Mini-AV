#include "Config.h"
#include "json.hpp"
#include <fstream>

using json = nlohmann::json;

namespace Config {
    void SaveConfig(const std::string filename) {
        json j;

        j["DebugWindow"] = Data.DebugWindow;
        j["ViewAlerts"] = Data.ViewAlerts;
        j["ViewLogs"] = Data.ViewLogs;

        j["ViewLogs"] = Data.ProtectedProc.Name;

        std::ofstream file(filename + ".cfg");
        file << j.dump(4);
        file.close();
    }

    void LoadConfig(const std::string filename) {
        std::ifstream file(filename + ".cfg");
        if (!file.is_open()) return;
        json j;
        file >> j;

        Data.DebugWindow = j.value("DebugWindow", Data.DebugWindow);
        Data.ViewAlerts = j.value("ViewAlerts", Data.ViewAlerts);
        Data.ViewLogs = j.value("ViewLogs", Data.ViewLogs);

        file.close();
    }
}