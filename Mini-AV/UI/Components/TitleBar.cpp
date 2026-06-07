#include "../UI.h"
#include "../Globals.h"

#include <Windows.h>

void UI::Components::TitleBar()
{
	ImGuiStyle& Style = ImGui::GetStyle();

	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, { 8.0f, 4.0f });
	ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, { Style.WindowPadding.x, Style.ItemSpacing.y });

	Globals::TitleBarHovered = false;

	if (ImGui::BeginChild("Custom title bar", { 0.0f, Globals::TitleBarHeight }, ImGuiChildFlags_Border, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse)) {
		// If another window (demo, debug panel, popup) is over the title bar, this is false,
		// so the WM_NCHITTEST handler won't steal its input for window dragging.
		Globals::TitleBarHovered = ImGui::IsWindowHovered();

		const float ButtonWidth = 40.0f;
		const float ItemSpacing = ImGui::GetStyle().ItemSpacing.x;
		const float ContentHeight = ImGui::GetContentRegionAvail().y;

		if (UI::FontLogo) {
			const ImU32 LogoColor = ImGui::GetColorU32(ImGuiCol_Text);
			const float LogoSize = UI::FontLogo->FontSize;
			const ImVec2 LogoTextSize = UI::FontLogo->CalcTextSizeA(LogoSize, FLT_MAX, 0.0f, "A");
			const ImVec2 LogoPos = {
				ImGui::GetCursorScreenPos().x,
				ImGui::GetCursorScreenPos().y + (ContentHeight - LogoTextSize.y) * 0.5f
			};
			ImDrawList* DrawList = ImGui::GetWindowDrawList();
			const ImVec2 LogoCenter = {
				LogoPos.x + LogoTextSize.x * 0.5f,
				LogoPos.y + LogoTextSize.y * 0.5f
			};
			DrawList->AddShadowCircle(LogoCenter, 5, LogoColor, 48.0f, { 0.0f, 0.0f }, 0);
			DrawList->AddText(UI::FontLogo, LogoSize, LogoPos, LogoColor, "A");
			ImGui::Dummy({ LogoTextSize.x, ContentHeight });
			ImGui::SameLine();
		}

		const float ButtonsTotalWidth = ButtonWidth * 3.0f + ItemSpacing * 3.0f;
		const float DragRegionWidth = ImGui::GetContentRegionAvail().x - ButtonsTotalWidth;

		if (DragRegionWidth > 20.0f) {
			ImGui::Dummy({ DragRegionWidth, ContentHeight });
			const ImVec2 Min = ImGui::GetItemRectMin();
			const ImVec2 Max = ImGui::GetItemRectMax();
			Globals::TitleBarDragRect = {
				static_cast<LONG>(Min.x),
				static_cast<LONG>(Min.y),
				static_cast<LONG>(Max.x),
				static_cast<LONG>(Max.y)
			};
			ImGui::SameLine();
		}
		else {
			Globals::TitleBarDragRect = {};
		}

		auto DrawTitleBarButton = [&](const char* Id, const char* Label, ImU32 ShadowColor) -> bool {
			const ImVec2 Pos = ImGui::GetCursorScreenPos();
			const bool Pressed = ImGui::InvisibleButton(Id, { ButtonWidth, ContentHeight });
			ImDrawList* DrawList = ImGui::GetWindowDrawList();
			if (ImGui::IsItemHovered() || ImGui::IsItemActive()) {
				const float Thickness = ImGui::IsItemActive() ? 12.0f : 32.0f;
				const ImVec2 Center = { Pos.x + ButtonWidth * 0.5f, Pos.y + ContentHeight * 0.5f };
				const float Radius = min(ButtonWidth, ContentHeight) * 0.15f;
				DrawList->AddShadowCircle(Center, Radius, ShadowColor, Thickness, { 0.0f, 0.0f }, 0, 24);
			}
			const ImVec2 LabelSize = ImGui::CalcTextSize(Label);
			const ImVec2 LabelPos = {
				Pos.x + (ButtonWidth - LabelSize.x) * 0.5f,
				Pos.y + (ContentHeight - LabelSize.y) * 0.5f
			};
			DrawList->AddText(LabelPos, ImGui::GetColorU32(ImGuiCol_Text), Label);
			return Pressed;
		};

		if (DrawTitleBarButton("##TitleMinimize", "-", IM_COL32(255, 255, 255, 150)))
			ShowWindow(Globals::MainWindowHandle, SW_MINIMIZE);
		ImGui::SameLine();
		if (DrawTitleBarButton("##TitleMaximize", IsZoomed(Globals::MainWindowHandle) ? "o" : "[]", IM_COL32(255, 255, 255, 150))) {
			if (IsZoomed(Globals::MainWindowHandle))
				ShowWindow(Globals::MainWindowHandle, SW_RESTORE);
			else
				ShowWindow(Globals::MainWindowHandle, SW_MAXIMIZE);
		}
		ImGui::SameLine();
		if (DrawTitleBarButton("##TitleClose", "X", IM_COL32(232, 17, 35, 255)))
			PostQuitMessage(0);
	}
	ImGui::EndChild();
	ImGui::PopStyleVar(2);
}
