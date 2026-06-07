#pragma once
#include "../UI.h"
#include <cstdint>

namespace UI::Components::Notifications {
	using NotificationId = std::uint64_t;

	void Push(const std::string& Title, const std::string& Message, NotificationType Type, float DurationSec = 0.0f);
	void RequestDismiss(NotificationId Id);
	bool HasActive();
	void Update(float DeltaSeconds);
	void Render();
}
