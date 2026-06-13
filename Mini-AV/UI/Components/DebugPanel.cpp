#include "DebugPanel.h"
#include "../../Alerts/Alerts.h"
#include "../../Config.h"
#include "../../Protections/Engines/TlshDatabase.h"

#include "imgui.h"

#include <string>

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

	// --- TLSH blacklist ------------------------------------------------------
	// Add a fuzzy-hash signature without hand-editing tlsh.json (which lives under
	// %ProgramData%\MiniAV with restricted perms). The elevated service can write
	// it, and the entry applies live — no restart.
	ImGui::SeparatorText("TLSH blacklist");
	ImGui::TextWrapped(
		"Paste a digest from the logs (\"TlshEngine: ... tlsh=T1...\") to blacklist it. "
		"Applies immediately and writes tlsh.json.");

	static char tlshBuf[128] = "";
	static char nameBuf[96] = "";
	static char familyBuf[96] = "";
	static int maxDistance = -1;
	static std::string status;

	ImGui::InputText("TLSH (T1...)", tlshBuf, sizeof(tlshBuf));
	ImGui::InputText("Name", nameBuf, sizeof(nameBuf));
	ImGui::InputText("Family", familyBuf, sizeof(familyBuf));
	ImGui::InputInt("Max distance (-1 = use global)", &maxDistance);
	if (maxDistance < -1)
		maxDistance = -1;

	if (ImGui::Button("Add to tlsh.json")) {
		if (tlshBuf[0] == '\0') {
			status = "TLSH string is empty.";
		} else if (TlshDatabase::AddEntry(tlshBuf, nameBuf, familyBuf, maxDistance)) {
			status = "Added and saved (live).";
			tlshBuf[0] = nameBuf[0] = familyBuf[0] = '\0';
			maxDistance = -1;
		} else {
			status = "Failed: invalid digest or write error (see logs).";
		}
	}

	ImGui::SameLine();
	ImGui::TextDisabled("entries: %zu", TlshDatabase::EntryCount());

	if (!status.empty())
		ImGui::TextWrapped("%s", status.c_str());

	ImGui::End();
}
