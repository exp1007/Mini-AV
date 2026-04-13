#include "../Globals.h"
#include "Logging.h"

#include <chrono>
#include <ctime>

void Logs::Add(std::string Data) {
    auto Now = std::chrono::system_clock::now();
    std::time_t NowC = std::chrono::system_clock::to_time_t(Now);
    char TimeBuffer[32];
    std::strftime(TimeBuffer, sizeof(TimeBuffer), "[%Y-%m-%d %H:%M:%S] ", std::localtime(&NowC));
    std::string FormattedString = std::string(TimeBuffer) + Data;

    Globals::Logs.push_back(FormattedString);
}

namespace TerminalLogs {
    static bool IsInitialized = false;

    void Initialize() {
        if (IsInitialized) return;

        AllocConsole();
        SetConsoleTitleA( "Mini-AV Console" );
        freopen_s( reinterpret_cast<FILE**>( stdout ), "CONOUT$", "w", stdout );
        freopen_s( reinterpret_cast<FILE**>( stderr ), "CONOUT$", "w", stderr );
        freopen_s( reinterpret_cast<FILE**>( stdin ), "CONIN$", "r", stdin );

        IsInitialized = true;
    }

    void Shutdown() {
        if (!IsInitialized) return;

        PostMessageA( GetConsoleWindow( ), WM_CLOSE, 0, 0 );
        FreeConsole();

        IsInitialized = false;
    }

    void Log( const char* File, int Line, WORD Color, const char* Fmt, ... ) {
        if (!IsInitialized) return;

        SYSTEMTIME Time;
        GetLocalTime( &Time );

        HANDLE HConsole = GetStdHandle( STD_OUTPUT_HANDLE );
        CONSOLE_SCREEN_BUFFER_INFO ConsoleInfo;
        GetConsoleScreenBufferInfo( HConsole, &ConsoleInfo );
        WORD OriginalAttrs = ConsoleInfo.wAttributes;

        printf( "[%02d:%02d:%02d] ", Time.wHour, Time.wMinute, Time.wSecond );

        const char* FileName = strrchr( File, '\\' );
        FileName = FileName ? FileName + 1 : File;

        SetConsoleTextAttribute( HConsole, Color );
        printf( "%s:%d:", FileName, Line );

        SetConsoleTextAttribute( HConsole, OriginalAttrs );
        printf( " " );

        va_list Args;
        va_start( Args, Fmt );
        vprintf( Fmt, Args );
        va_end( Args );
        
        printf( "\n" );
    }
}