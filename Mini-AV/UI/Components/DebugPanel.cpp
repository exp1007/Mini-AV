#include "DebugPanel.h"
#include "../../Alerts/Alerts.h"
#include "../../Config.h"

#include "imgui.h"

void UI::Components::DebugPanel()
{
	if (!Config::Data.DebugPanelWindow)
		return;

	if (!ImGui::Begin("Debug panel", &Config::Data.DebugPanelWindow)) {
		ImGui::End();
		return;
	}

	ImGui::SeparatorText("Alerts");

	if (ImGui::Button("Send example alert (critical)"))
		Alerts::Add("Execution blocked: C:\\Users\\Public\\MiniAvBlockTest.exe", AlertRisk::high);

	if (ImGui::Button("Send example alert (warning)"))
		Alerts::Add("Suspicious handle access detected on protected process", AlertRisk::medium);

	if (ImGui::Button("Send example alert (info)"))
		Alerts::Add("Protection scan completed with no threats found", AlertRisk::low);

	ImGui::End();
}
