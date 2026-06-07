#include "Alerts.h"
#include "../Globals.h"
#include "../Logging/Logging.h"
#include "../UI/Components/Notifications.h"

#include <mutex>

namespace {
	std::mutex AlertsMutex;
}

// Single sink for user-facing security events. Fans out to:
//   1. the Alerts panel  (Globals::Alerts)
//   2. a toast notification (Notifications::Push)
//   3. the in-app Logs panel (Logs::Add), so the event is also kept in the log
// Terminal (console) logging stays at the call site, where the structured
// pid/subtype context is available.
void Alerts::Add(std::string details, AlertRisk risk, std::string toastTitle, std::string toastBody) {
	AlertEntity Alert{ details, risk };
	{
		std::lock_guard<std::mutex> Lock(AlertsMutex);
		Globals::Alerts.push_back(Alert);
	}

	UI::Components::NotificationType Type = UI::Components::NotificationType::Info;
	const char* DefaultTitle = "Notice";
	if (risk == AlertRisk::medium) {
		Type = UI::Components::NotificationType::Warning;
		DefaultTitle = "Warning";
	} else if (risk == AlertRisk::high) {
		Type = UI::Components::NotificationType::Critical;
		DefaultTitle = "Threat blocked";
	}

	// Toast = short category + (optionally) the file name. Falls back to the full
	// details only when no concise summary was supplied (e.g. DebugPanel examples).
	const std::string title = toastTitle.empty() ? std::string(DefaultTitle) : toastTitle;
	const std::string body = !toastBody.empty()
		? toastBody
		: (toastTitle.empty() ? details : std::string());

	UI::Components::Notifications::Push(title, body, Type);
	Logs::Add(std::string("[ALERT] ") + details);
}

std::vector<AlertEntity> Alerts::GetSnapshot()
{
	std::lock_guard<std::mutex> Lock(AlertsMutex);
	return Globals::Alerts;
}