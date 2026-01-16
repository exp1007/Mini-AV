#include "Alerts.h"
#include "../Globals.h"

void Alerts::Add(std::string details, AlertRisk risk) {
	AlertEntity a{ details, risk };
	Globals::Alerts.push_back(a);
}