#include "UI.h"
#include "Globals.h"
#include "../Utils/Utils.h"
#include "../Logs/Logs.h"
#include "../Config.h"
#include "../Alerts/Alerts.h"
#include "../Protections/Protections.h"

#include <string>
#include <vector>
#include <algorithm>

void UI::Components::MainWindow() {

	ImGuiStyle& Style = ImGui::GetStyle();

	ImGui::SetNextWindowPos({0,0}, ImGuiCond_Always);
	ImGui::SetNextWindowSize(Globals::ClientSize);
	ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0);

	ImGui::Begin("Main window", nullptr, ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoResize);

	if (ImGui::BeginMenuBar()) {
		if (ImGui::BeginMenu("View")) {
			ImGui::MenuItem("Alerts", NULL, &Config::Data.ViewAlerts);
			ImGui::MenuItem("Logs", NULL, &Config::Data.ViewLogs);
			ImGui::EndMenu();
		}

		if (ImGui::BeginMenu("UI Framework")) {
			ImGui::MenuItem("Demo window", NULL, &Config::Data.DebugWindow);
			ImGui::MenuItem("Styles window", NULL, &Config::Data.StylesWindow);
			ImGui::MenuItem("Config window", NULL, &Config::Data.ConfigsWindow);
			ImGui::EndMenu();
		}

		ImGui::EndMenuBar();
	}

	// Childs
	ImVec2 ChildSize = ImGui::GetWindowSize();
	ChildSize.x = ChildSize.x / 2 - Style.WindowPadding.x - Style.WindowPadding.x / 2;
	ChildSize.y = ChildSize.y / 2 - Style.WindowPadding.y * 2;

	if (ImGui::BeginChild("First child", { ChildSize.x,0 }, ImGuiChildFlags_Border)) {
		ImGui::Checkbox("Enable protection", &Config::Data.IsProtected);

		ImGui::SeparatorText("Setup");

		ImGui::SetNextWindowSizeConstraints({ 0,0 }, { FLT_MAX,500 });

		static std::vector<ProcEntity> LocalProcessList;
		if (ImGui::BeginPopup("Process list popup")) {
			static char SearchBuff[255] = "";
			ImGui::InputText("Search...", SearchBuff, IM_ARRAYSIZE(SearchBuff));
			std::string StrSearchBuff(SearchBuff);

			if (ImGui::BeginListBox("##Process list")) {
				for (auto& Proc : LocalProcessList) {
					// Filter
					if (StrSearchBuff.size() > 0) {
						if (Utils::StrToLower(Proc.Name).find(Utils::StrToLower(StrSearchBuff)) == std::string::npos)
							continue;
					}

					std::string FormatedProc;
					bool IsSelected = false;
					FormatedProc += std::to_string(Proc.PID) + " | " + Proc.Name;
					if (ImGui::Selectable(FormatedProc.c_str(), IsSelected)) {
						Config::Data.ProtectedProc = Proc;
						Logs::Add("Selected protected process: " + Proc.Name + " (" + std::to_string(Proc.PID) + ")");
					}

				}

				ImGui::EndListBox(); 
			}

			if (ImGui::Button("Refresh"))
				LocalProcessList = Utils::GetProcessList();

			ImGui::EndPopup();
		}

		if (ImGui::BeginChild("Current process", { ImGui::CalcItemWidth() ,100 }, ImGuiChildFlags_FrameStyle)) {
			ImGui::Text("Process name: %s", Config::Data.ProtectedProc.Name.c_str());
			ImGui::Text("PID: %d", Config::Data.ProtectedProc.PID);
			ImGui::EndChild();
		}


		if (ImGui::Button("Select process")) {
			ImGui::OpenPopup("Process list popup");
			LocalProcessList = Utils::GetProcessList();
		}

		ImGui::SeparatorText("Protections");
		ImGui::SliderInt("Scan delay (sec)", &Globals::ScanDelay, 0, 10);

	}
	ImGui::EndChild();

	ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, { Style.WindowPadding.x, Style.ItemSpacing.y });
	ImGui::SameLine();

	if (ImGui::BeginChild("Second child", { ChildSize.x,0 }, ImGuiChildFlags_Border)) {

		// Alerts terminal
		if (Config::Data.ViewAlerts) {
			ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, { 14, 4 });
			ImGui::Text("Alerts");

			ImGui::BeginChild("Alerts terminal", { 0,200 }, ImGuiChildFlags_FrameStyle);

			ImGuiListClipper clipper;
			clipper.Begin(Globals::Alerts.size());
			while (clipper.Step())
				for (int line_no = clipper.DisplayStart; line_no < clipper.DisplayEnd; line_no++)
					ImGui::Text(Globals::Alerts[line_no].Details.c_str());

			ImGui::EndChild();
			ImGui::PopStyleVar();
		}

		// Logs terminal
		if (Config::Data.ViewLogs) {
			ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, { 14, 4 });
			ImGui::Text("Logs terminal");

			ImGui::BeginChild("Logs terminal", { 0,200 }, ImGuiChildFlags_FrameStyle);

			ImGuiListClipper clipper;
			clipper.Begin(Globals::Logs.size());
			while (clipper.Step())
				for (int line_no = clipper.DisplayStart; line_no < clipper.DisplayEnd; line_no++)
					ImGui::Text(Globals::Logs[line_no].c_str());
			
			ImGui::EndChild();
			ImGui::PopStyleVar();
		}

	}
	ImGui::EndChild();
	ImGui::PopStyleVar();

	ImGui::End();

	// Cleaning pushes
	ImGui::PopStyleVar();
}

void UI::Components::Configs() {
	ImGui::Begin("Configs", &Config::Data.ConfigsWindow);

	static char ConfigName[255] = { };
	ImGui::InputText("Config name", ConfigName, 255);
	if (ImGui::Button("Save config", {0,0}))
		Config::SaveConfig(ConfigName);
	if(ImGui::Button("Load config"))
		Config::LoadConfig(ConfigName);

	ImGui::End();
}