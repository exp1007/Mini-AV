#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>
#include <stdarg.h>

#include <string>

namespace Logs {
	void Add(std::string Data);
}

namespace TerminalLogs {
    void Initialize();
    void Shutdown();
    void Log( const char* File, int Line, WORD Color, const char* Fmt, ... );
}

#define LOG(fmt, ...) TerminalLogs::Log(__FILE__, __LINE__, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE, fmt, __VA_ARGS__)
#define LOG_ERROR(fmt, ...) TerminalLogs::Log(__FILE__, __LINE__, FOREGROUND_INTENSITY | FOREGROUND_RED, fmt, __VA_ARGS__)
#define LOG_WARNING(fmt, ...) TerminalLogs::Log(__FILE__, __LINE__, FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN, fmt, __VA_ARGS__)
#define LOG_SUCCESS(fmt, ...) TerminalLogs::Log(__FILE__, __LINE__, FOREGROUND_INTENSITY | FOREGROUND_GREEN, fmt, __VA_ARGS__)
#define LOG_INFO(fmt, ...) TerminalLogs::Log(__FILE__, __LINE__, FOREGROUND_INTENSITY | FOREGROUND_BLUE, fmt, __VA_ARGS__)
