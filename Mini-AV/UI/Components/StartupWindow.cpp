#include "../UI.h"
#include "../Globals.h"
#include "../../Utils/Driver/Setup.h"

#include <Windows.h>
#include <cfloat>

namespace {
	// Compact loader footprint, plus a taller variant used when the driver fails
	// and we need room for the detail log and the retry/exit buttons.
	constexpr int LoaderWidth = 460;
	constexpr int LoaderHeight = 280;
	constexpr int FailedWidth = 460;
	constexpr int FailedHeight = 470;

	// Dashboard size to expand into once startup succeeds.
	constexpr int DashboardWidth = 1280;
	constexpr int DashboardHeight = 800;

	constexpr double PhaseDuration = 0.55; // Seconds each check stays in "Checking".
	constexpr int PhaseCount = 4;

	void CenterWindow(int Width, int Height)
	{
		HWND Hwnd = Globals::MainWindowHandle;
		if (!Hwnd)
			return;

		HMONITOR Monitor = MonitorFromWindow(Hwnd, MONITOR_DEFAULTTONEAREST);
		MONITORINFO Info{ sizeof(Info) };
		if (!GetMonitorInfo(Monitor, &Info))
			return;

		const int WorkWidth = Info.rcWork.right - Info.rcWork.left;
		const int WorkHeight = Info.rcWork.bottom - Info.rcWork.top;
		const int X = Info.rcWork.left + (WorkWidth - Width) / 2;
		const int Y = Info.rcWork.top + (WorkHeight - Height) / 2;
		SetWindowPos(Hwnd, nullptr, X, Y, Width, Height, SWP_NOZORDER);
	}

	void DrawStateLine(const char* Label, bool Revealed, bool IsOk, const char* OkText, const char* FailText)
	{
		const ImVec4 Pending = ImVec4(0.55f, 0.55f, 0.58f, 1.0f);
		const ImVec4 Good = ImVec4(0.20f, 0.75f, 0.30f, 1.0f);
		const ImVec4 Bad = ImVec4(0.85f, 0.28f, 0.28f, 1.0f);

		ImGui::Text("%s", Label);

		const char* Status = !Revealed ? "Checking" : (IsOk ? OkText : FailText);
		const ImVec4 Color = !Revealed ? Pending : (IsOk ? Good : Bad);

		const float TextWidth = ImGui::CalcTextSize(Status).x;
		ImGui::SameLine();
		ImGui::SetCursorPosX(ImGui::GetContentRegionMax().x - TextWidth);
		ImGui::TextColored(Color, "%s", Status);
	}
}

bool UI::Components::StartupWindow(UI::StartupState& StartupDetails)
{
	static double StartTime = -1.0;
	static bool LoaderSized = false;
	static bool FailedSized = false;

	bool ContinueToMainWindow = false;

	const double Now = ImGui::GetTime();
	if (StartTime < 0.0)
		StartTime = Now;

	if (!LoaderSized) {
		CenterWindow(LoaderWidth, LoaderHeight);
		LoaderSized = true;
	}

	const double TotalDuration = PhaseCount * PhaseDuration;
	const double Elapsed = Now - StartTime;
	const bool AnimationDone = Elapsed >= TotalDuration;
	const int RevealedPhases = AnimationDone ? PhaseCount : static_cast<int>(Elapsed / PhaseDuration);

	const bool DriverAvailable = StartupDetails.DriverConnected && StartupDetails.DriverPingOk;
	const bool Failed = AnimationDone && !DriverAvailable;

	float Progress = static_cast<float>(Elapsed / TotalDuration);
	if (Progress > 1.0f)
		Progress = 1.0f;

	ImGui::SetNextWindowPos({ 0.0f, 0.0f }, ImGuiCond_Always);
	ImGui::SetNextWindowSize(Globals::ClientSize, ImGuiCond_Always);

	ImGuiWindowFlags Flags = ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar;
	ImGui::Begin("Mini-AV Startup", nullptr, Flags);
	UI::Components::TitleBar();
	{
		ImGuiStyle& Style = ImGui::GetStyle();
		ImGui::SetCursorPosY(ImGui::GetCursorPosY() + Style.WindowPadding.x - Style.ItemSpacing.y);
	}

	const char* Caption =
		Failed ? "Driver unavailable" :
		AnimationDone ? "Ready" :
		"Starting Mini-AV";
	ImGui::Text("%s", Caption);
	ImGui::Spacing();

	const ImVec4 BarColor = Failed ? ImVec4(0.85f, 0.28f, 0.28f, 1.0f) : ImVec4(0.20f, 0.65f, 0.95f, 1.0f);
	ImGui::PushStyleColor(ImGuiCol_PlotHistogram, BarColor);
	ImGui::ProgressBar(Progress, ImVec2(-FLT_MIN, 8.0f), "");
	ImGui::PopStyleColor();

	ImGui::Spacing();
	ImGui::Spacing();

	DrawStateLine("Settings file", RevealedPhases > 0, StartupDetails.ConfigFileFound, "Detected", "Not found");
	DrawStateLine("Settings load", RevealedPhases > 1, StartupDetails.ConfigLoaded, "Loaded", "Defaults");
	DrawStateLine("Driver port", RevealedPhases > 2, StartupDetails.DriverConnected, "Connected", "Disconnected");
	DrawStateLine("Driver ping", RevealedPhases > 3, StartupDetails.DriverPingOk, "Healthy", "Unavailable");

	if (Failed) {
		if (!FailedSized) {
			CenterWindow(FailedWidth, FailedHeight);
			FailedSized = true;
		}

		ImGui::Spacing();
		ImGui::SeparatorText("Startup details");
		if (ImGui::BeginChild("Startup details child", { 0.0f, 150.0f }, ImGuiChildFlags_FrameStyle)) {
			for (const auto& Message : StartupDetails.StatusMessages)
				ImGui::TextWrapped("- %s", Message.c_str());
		}
		ImGui::EndChild();
	}

	if (AnimationDone && DriverAvailable) {
		// Everything checks out, expand the window into the dashboard.
		CenterWindow(DashboardWidth, DashboardHeight);
		ContinueToMainWindow = true;
	}
	else {
		ImGui::Spacing();

		if (Failed) {
			if (ImGui::Button("Retry driver connection")) {
				Driver::SetupResult DriverState = Driver::RetryConnection();
				StartupDetails.DriverConnected = DriverState.Connected;
				StartupDetails.DriverPingOk = DriverState.PingOk;
				StartupDetails.StatusMessages.insert(
					StartupDetails.StatusMessages.end(),
					DriverState.Details.begin(),
					DriverState.Details.end());

				// Replay the loader animation against the refreshed state.
				StartTime = -1.0;
				FailedSized = false;
				CenterWindow(LoaderWidth, LoaderHeight);
			}
			ImGui::SameLine();

#ifdef _DEBUG
			// Debug-only escape hatch: enter the dashboard without a working driver.
			if (ImGui::Button("Continue anyway (debug)")) {
				CenterWindow(DashboardWidth, DashboardHeight);
				ContinueToMainWindow = true;
			}
			ImGui::SameLine();
#endif
		}

		// Exit stays available throughout loading and on failure.
		if (ImGui::Button("Exit"))
			PostQuitMessage(0);
	}

	ImGui::End();

	return ContinueToMainWindow;
}
