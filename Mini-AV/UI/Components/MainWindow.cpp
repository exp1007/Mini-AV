#include "../UI.h"
#include "../Globals.h"
#include "../Utils/Utils.h"
#include "../Logging/Logging.h"
#include "../Config.h"
#include "../Alerts/Alerts.h"
#include "../Protections/Protections.h"
#include "../Protections/Engines/EngineSettings.h"

#include <string>
#include <vector>
#include <algorithm>

namespace {

// Master/feature toggle row: a checkbox plus a coloured On/Off state label so the
// dashboard reads at a glance. Returns true when toggled (caller persists).
bool ToggleRow(const char* Label, bool* Value)
{
	const bool Changed = ImGui::Checkbox(Label, Value);
	ImGui::SameLine(280.0f);
	const ImVec4 Color = *Value ? ImVec4(0.20f, 0.75f, 0.30f, 1.0f) : ImVec4(0.60f, 0.60f, 0.62f, 1.0f);
	ImGui::TextColored(Color, *Value ? "On" : "Off");
	return Changed;
}

void DrawEngineColumn()
{
	EngineSettings::Settings& E = EngineSettings::Current;

	// --- Master switch -------------------------------------------------------
	ImGui::SeparatorText("Real-time protection");
	if (ToggleRow("Enable real-time protection", &E.RealtimeProtection))
		Config::SaveConfig();
	ImGui::TextDisabled("Master switch for file-create scanning. Off = nothing is scanned or blocked.");

	// --- Sensitivity / thresholds -------------------------------------------
	ImGui::SeparatorText("Sensitivity");

	const char* PresetItems[] = { "Low", "Balanced", "Aggressive", "Custom" };
	int PresetIdx = static_cast<int>(E.Preset);
	if (ImGui::Combo("Detection level", &PresetIdx, PresetItems, IM_ARRAYSIZE(PresetItems))) {
		E.Preset = static_cast<EngineSettings::Sensitivity>(PresetIdx);
		EngineSettings::ApplyPreset(E.Preset);
		Config::SaveConfig();
	}

	if (E.Preset == EngineSettings::Sensitivity::Custom) {
		bool ThresholdChanged = false;
		ThresholdChanged |= ImGui::SliderInt("Suspicious >=", &E.Suspicious, 1, 100);
		ThresholdChanged |= ImGui::SliderInt("Dangerous >=", &E.Dangerous, 1, 100);
		ThresholdChanged |= ImGui::SliderInt("Block >=", &E.Block, 1, 100);
		if (ThresholdChanged) {
			// Keep the bands monotonic: block >= dangerous >= suspicious.
			E.Dangerous = max(E.Dangerous, E.Suspicious);
			E.Block = max(E.Block, E.Dangerous);
			Config::SaveConfig();
		}
	}
	else {
		ImGui::TextDisabled("suspicious >= %d   dangerous >= %d   block >= %d",
			E.Suspicious, E.Dangerous, E.Block);
	}

	// Block action.
	const char* ActionItems[] = { "Quarantine file", "Deny access only" };
	int ActionIdx = E.ApplyQuarantine ? 0 : 1;
	if (ImGui::Combo("On block", &ActionIdx, ActionItems, IM_ARRAYSIZE(ActionItems))) {
		E.ApplyQuarantine = (ActionIdx == 0);
		Config::SaveConfig();
	}

	// --- Per-engine toggles --------------------------------------------------
	ImGui::SeparatorText("Detection engines");
	ImGui::BeginDisabled(!E.RealtimeProtection);
	if (ImGui::Checkbox("SHA-256 deny-list (definitive)", &E.UseHashDenyList)) Config::SaveConfig();
	if (ImGui::Checkbox("Context heuristics (entropy / path / MOTW)", &E.UseContextEngine)) Config::SaveConfig();
	if (ImGui::Checkbox("Capability / IAT analysis", &E.UseCapabilityEngine)) Config::SaveConfig();
	if (ImGui::Checkbox("Anti-debug detection", &E.UseAntiDebugEngine)) Config::SaveConfig();
	ImGui::EndDisabled();
}

// NOTE: The process / handle-protection UI was intentionally removed from the
// dashboard. The backend (Config::Data.IsProtected / ProtectedProc, the handle
// scanner in Protections::Manager + Handles.cpp, Globals::ScanDelay) is left in
// place so the selector can be re-added later — see git history for the previous
// DrawProcessProtectionColumn() implementation.

void DrawMonitorColumn()
{
	if (ImGui::BeginMenuBar()) {
		if (ImGui::BeginMenu("View")) {
			if (ImGui::MenuItem("Alerts", NULL, &Config::Data.ViewAlerts)) Config::SaveConfig();
			if (ImGui::MenuItem("Logs", NULL, &Config::Data.ViewLogs)) Config::SaveConfig();
			if (ImGui::MenuItem("Console Logs", NULL, &Config::Data.ViewConsoleLogs)) {
				if (Config::Data.ViewConsoleLogs)
					TerminalLogs::Initialize();
				else
					TerminalLogs::Shutdown();
				Config::SaveConfig();
			}
			ImGui::EndMenu();
		}

		if (ImGui::BeginMenu("UI Framework")) {
			if (ImGui::MenuItem("Demo window", NULL, &Config::Data.DebugWindow)) Config::SaveConfig();
			if (ImGui::MenuItem("Debug panel", NULL, &Config::Data.DebugPanelWindow)) Config::SaveConfig();
			if (ImGui::MenuItem("Styles window", NULL, &Config::Data.StylesWindow)) Config::SaveConfig();
			ImGui::EndMenu();
		}

		ImGui::EndMenuBar();
	}

	// Alerts terminal.
	if (Config::Data.ViewAlerts) {
		const std::vector<AlertEntity> AlertSnapshot = Alerts::GetSnapshot();

		ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, { 14, 4 });
		ImGui::Text("Alerts");
		ImGui::BeginChild("Alerts terminal", { 0, 200 }, ImGuiChildFlags_FrameStyle);

		ImGuiListClipper clipper;
		clipper.Begin(static_cast<int>(AlertSnapshot.size()));
		while (clipper.Step())
			for (int line_no = clipper.DisplayStart; line_no < clipper.DisplayEnd; line_no++)
				ImGui::TextUnformatted(AlertSnapshot[line_no].Details.c_str());

		ImGui::EndChild();
		ImGui::PopStyleVar();
	}

	// Logs terminal.
	if (Config::Data.ViewLogs) {
		ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, { 14, 4 });
		ImGui::Text("Logs terminal");
		ImGui::BeginChild("Logs terminal", { 0, 200 }, ImGuiChildFlags_FrameStyle);

		const std::vector<std::string> UiLogs = Logs::GetSnapshot();

		ImGuiListClipper clipper;
		clipper.Begin(static_cast<int>(UiLogs.size()));
		while (clipper.Step())
			for (int line_no = clipper.DisplayStart; line_no < clipper.DisplayEnd; line_no++)
				ImGui::TextUnformatted(UiLogs[line_no].c_str());

		ImGui::EndChild();
		ImGui::PopStyleVar();
	}

	if (!Config::Data.ViewAlerts && !Config::Data.ViewLogs)
		ImGui::TextDisabled("Enable Alerts or Logs from the View menu.");
}

}

void UI::Components::MainWindow() {

	ImGuiStyle& Style = ImGui::GetStyle();

	ImGui::SetNextWindowPos({ 0, 0 }, ImGuiCond_Always);
	ImGui::SetNextWindowSize(Globals::ClientSize);

	ImGui::Begin("Main window", nullptr, ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize);
	UI::Components::TitleBar();
	ImGui::SetCursorPosY(ImGui::GetCursorPosY() + Style.WindowPadding.x - Style.ItemSpacing.y);

	// Two columns: left = configuration (engine + process protection), right = monitor.
	ImVec2 ChildSize = ImGui::GetWindowSize();
	ChildSize.x = ChildSize.x / 2 - Style.WindowPadding.x - Style.WindowPadding.x / 2;

	if (ImGui::BeginChild("Configuration", { ChildSize.x, 0 }, ImGuiChildFlags_Border)) {
		DrawEngineColumn();
	}
	ImGui::EndChild();

	ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, { Style.WindowPadding.x, Style.ItemSpacing.y });
	ImGui::SameLine();

	if (ImGui::BeginChild("Monitor", { ChildSize.x, 0 }, ImGuiChildFlags_Border, ImGuiWindowFlags_MenuBar)) {
		DrawMonitorColumn();
	}
	ImGui::EndChild();
	ImGui::PopStyleVar();

	ImGui::End();
}
