#pragma once

#include <string>

namespace Quarantine {

bool Initialize();
void Shutdown();
bool IsQuarantinePath(const std::wstring& Path);
bool IsManagedPath(const std::wstring& Path);
bool MoveToQuarantine(const std::wstring& SourcePath, std::wstring& OutQuarantinePath);

}
