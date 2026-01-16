#pragma once
#include <string>

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
	void Add(std::string details, AlertRisk risk);
}