#include "../Globals.h"
#include "Logging.h"

#include <chrono>
#include <ctime>

void Logs::Add(std::string data) {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    char timeBuffer[32];
    std::strftime(timeBuffer, sizeof(timeBuffer), "[%Y-%m-%d %H:%M:%S] ", std::localtime(&now_c));
    std::string formattedString = std::string(timeBuffer) + data;

    Globals::Logs.push_back(formattedString);
}