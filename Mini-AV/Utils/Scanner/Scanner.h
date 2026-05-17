#pragma once

#include <Windows.h>

#include "MiniAvFilterMessages.h"

namespace Scanner {
	void Start();
	void Stop();
	void EnqueueBlockedFile(const MINIAV_CREATE_DECISION_REQUEST& Request);
}
