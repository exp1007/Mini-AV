#pragma once
#include <string>
#include <vector>

enum AlertRisk {
	none,
	low,
	medium,
	high
};

struct AlertEntity {
	std::string Details;
	AlertRisk RiskLevel;
};

namespace Alerts {
	// details    -> full text kept in the Alerts panel + Logs panel.
	// toastTitle -> toast heading; empty = default heading derived from risk
	//               ("Threat blocked" / "Warning" / "Notice").
	// toastBody  -> short toast line (the detection category). Empty falls back to
	//               the full details only when no title was given either.
	// The toast deliberately shows just the category, never the full detail, so it
	// stays small; the breakdown lives in the panel/logs.
	void Add(std::string details, AlertRisk risk, std::string toastTitle = "", std::string toastBody = "");
	std::vector<AlertEntity> GetSnapshot();
}