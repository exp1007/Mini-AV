#include "../UI.h"
#include "../Globals.h"
#include "../../Utils/Driver/Setup.h"

#include <Windows.h>

namespace {
	void DrawStateLine(const char* Label, bool IsOk, const char* OkText, const char* FailText)
	{
		ImGui::Text("%s", Label);
		ImGui::SameLine(280.0f);
		const ImVec4 Color = IsOk ? ImVec4(0.20f, 0.75f, 0.30f, 1.0f) : ImVec4(0.85f, 0.28f, 0.28f, 1.0f);
		ImGui::TextColored(Color, "%s", IsOk ? OkText : FailText);
	}
}

bool UI::Components::StartupWindow(UI::StartupState& StartupDetails)
{
	bool ContinueToMainWindow = false;

	ImGui::SetNextWindowPos({ 0.0f, 0.0f }, ImGuiCond_Always);
	ImGui::SetNextWindowSize(Globals::ClientSize, ImGuiCond_Always);

	ImGuiWindowFlags Flags = ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar;
	ImGui::Begin("Mini-AV Startup", nullptr, Flags);
	UI::Components::TitleBar();
	{
		ImGuiStyle& Style = ImGui::GetStyle();
		ImGui::SetCursorPosY(ImGui::GetCursorPosY() + Style.WindowPadding.x - Style.ItemSpacing.y);
	}

	ImGui::SeparatorText("Loader state");
	DrawStateLine("Settings file", StartupDetails.ConfigFileFound, "Detected", "Not found");
	DrawStateLine("Settings load", StartupDetails.ConfigLoaded, "Loaded", "Defaults in use");
	DrawStateLine("Driver port", StartupDetails.DriverConnected, "Connected", "Disconnected");
	DrawStateLine("Driver ping", StartupDetails.DriverPingOk, "Healthy", "Unavailable");

	ImGui::Spacing();
	ImGui::SeparatorText("Startup details");
	if (ImGui::BeginChild("Startup details child", { 0.0f, 230.0f }, ImGuiChildFlags_FrameStyle)) {
		for (const auto& Message : StartupDetails.StatusMessages)
			ImGui::TextWrapped("- %s", Message.c_str());
	}
	ImGui::EndChild();

	if (ImGui::Button("Retry driver connection")) {
		Driver::SetupResult DriverState = Driver::RetryConnection();
		StartupDetails.DriverConnected = DriverState.Connected;
		StartupDetails.DriverPingOk = DriverState.PingOk;
		StartupDetails.StatusMessages.insert(
			StartupDetails.StatusMessages.end(),
			DriverState.Details.begin(),
			DriverState.Details.end());
	}

	ImGui::SameLine();
	if (ImGui::Button("Continue to dashboard"))
		ContinueToMainWindow = true;

	ImGui::SameLine();
	if (ImGui::Button("Exit"))
		PostQuitMessage(0);

	ImGui::End();

	return ContinueToMainWindow;
}
