#include "Notifications.h"

#include <algorithm>
#include <cfloat>
#include <deque>
#include <mutex>
#include <unordered_set>
#include <vector>

namespace {
	struct NotificationEntry {
		UI::Components::Notifications::NotificationId Id = 0;
		std::string Title;
		std::string Message;
		UI::Components::NotificationType Type = UI::Components::NotificationType::Info;
		float DurationSec = 5.0f;
		float ElapsedSec = 0.0f;
	};

	std::mutex NotificationsMutex;
	std::deque<NotificationEntry> NotificationsQueue;
	std::unordered_set<UI::Components::Notifications::NotificationId> PendingDismiss;
	UI::Components::Notifications::NotificationId NextNotificationId = 1;

	constexpr float InfoDurationSec = 5.0f;
	constexpr float WarningDurationSec = 8.0f;
	constexpr float CriticalDurationSec = 14.0f;
	constexpr float FadeInDurationSec = 0.18f;
	constexpr float FadeOutDurationSec = 0.4f;
	constexpr size_t MaxNotifications = 5;

	float GetDefaultDuration(UI::Components::NotificationType Type)
	{
		switch (Type) {
		case UI::Components::NotificationType::Warning:
			return WarningDurationSec;
		case UI::Components::NotificationType::Critical:
			return CriticalDurationSec;
		case UI::Components::NotificationType::Info:
		default:
			return InfoDurationSec;
		}
	}

	ImVec4 GetAccentColor(UI::Components::NotificationType Type)
	{
		switch (Type) {
		case UI::Components::NotificationType::Warning:
			return ImVec4(1.0f, 0.74f, 0.24f, 1.0f);
		case UI::Components::NotificationType::Critical:
			return ImVec4(0.95f, 0.25f, 0.28f, 1.0f);
		case UI::Components::NotificationType::Info:
		default:
			return ImVec4(0.35f, 0.65f, 0.96f, 1.0f);
		}
	}

	// Short severity word shown as an accent-colored prefix in the title row, so
	// the user can tell warning vs critical at a glance regardless of the title text.
	const char* GetTypeLabel(UI::Components::NotificationType Type)
	{
		switch (Type) {
		case UI::Components::NotificationType::Warning:
			return "WARNING";
		case UI::Components::NotificationType::Critical:
			return "CRITICAL";
		case UI::Components::NotificationType::Info:
		default:
			return "INFO";
		}
	}

	// Draws a crisp, perfectly-centered severity glyph inside the icon circle.
	void DrawTypeIcon(ImDrawList* DrawList, ImVec2 Center, float Radius, UI::Components::NotificationType Type, ImU32 Col)
	{
		const float Thickness = 1.8f;
		switch (Type) {
		case UI::Components::NotificationType::Critical: {
			// "×" — two diagonal strokes, centered on the circle
			const float D = Radius * 0.5f;
			DrawList->AddLine(ImVec2(Center.x - D, Center.y - D), ImVec2(Center.x + D, Center.y + D), Col, Thickness);
			DrawList->AddLine(ImVec2(Center.x - D, Center.y + D), ImVec2(Center.x + D, Center.y - D), Col, Thickness);
			break;
		}
		case UI::Components::NotificationType::Warning: {
			// "!" — stem on top, dot below
			DrawList->AddLine(ImVec2(Center.x, Center.y - Radius * 0.55f), ImVec2(Center.x, Center.y + Radius * 0.10f), Col, Thickness);
			DrawList->AddCircleFilled(ImVec2(Center.x, Center.y + Radius * 0.50f), Thickness * 0.75f, Col, 8);
			break;
		}
		case UI::Components::NotificationType::Info:
		default: {
			// "i" — dot on top, stem below
			DrawList->AddCircleFilled(ImVec2(Center.x, Center.y - Radius * 0.50f), Thickness * 0.75f, Col, 8);
			DrawList->AddLine(ImVec2(Center.x, Center.y - Radius * 0.10f), ImVec2(Center.x, Center.y + Radius * 0.55f), Col, Thickness);
			break;
		}
		}
	}
}

void UI::Components::Notifications::Push(const std::string& Title, const std::string& Message, NotificationType Type, float DurationSec)
{
	std::lock_guard<std::mutex> Lock(NotificationsMutex);

	NotificationEntry Entry;
	Entry.Id = NextNotificationId++;
	Entry.Title = Title;
	Entry.Message = Message;
	Entry.Type = Type;
	Entry.DurationSec = DurationSec > 0.0f ? DurationSec : GetDefaultDuration(Type);
	Entry.ElapsedSec = 0.0f;
	NotificationsQueue.push_back(std::move(Entry));

	while (NotificationsQueue.size() > MaxNotifications)
		NotificationsQueue.pop_front();
}

void UI::Components::Notifications::RequestDismiss(NotificationId Id)
{
	std::lock_guard<std::mutex> Lock(NotificationsMutex);
	PendingDismiss.insert(Id);
}

bool UI::Components::Notifications::HasActive()
{
	std::lock_guard<std::mutex> Lock(NotificationsMutex);
	return !NotificationsQueue.empty();
}

void UI::Components::Notifications::Update(float DeltaSeconds)
{
	std::lock_guard<std::mutex> Lock(NotificationsMutex);

	for (auto& Entry : NotificationsQueue)
		Entry.ElapsedSec += DeltaSeconds;

	NotificationsQueue.erase(
		std::remove_if(
			NotificationsQueue.begin(),
			NotificationsQueue.end(),
			[](const NotificationEntry& Entry)
			{
				return PendingDismiss.find(Entry.Id) != PendingDismiss.end() || Entry.ElapsedSec >= Entry.DurationSec;
			}),
		NotificationsQueue.end());

	PendingDismiss.clear();
}

void UI::Components::Notifications::Render()
{
	const ImVec2 DisplaySize = ImGui::GetIO().DisplaySize;

	// Layout constants
	constexpr float MarginX = 14.0f;     // gap from window left/right edge
	constexpr float MarginBottom = 14.0f; // gap from bottom edge
	constexpr float CardPadding = 14.0f;  // inner padding
	constexpr float AccentBarWidth = 4.0f;
	constexpr float CardRounding = 8.0f;
	constexpr float CardGap = 10.0f;
	constexpr float ProgressBarHeight = 3.0f;
	constexpr float IconRadius = 9.0f;
	constexpr float IconGap = 10.0f;       // gap between icon and title text
	constexpr float TitleToMsgGap = 9.0f;  // gap below title before message
	constexpr float ShadowOffset = 4.0f;

	const float CardWidth = DisplaySize.x - MarginX * 2.0f;
	const float CardX = MarginX;
	// Icon sits just inside the accent bar + padding; the title sits to its right.
	const float IconLeftX = CardX + AccentBarWidth + CardPadding;
	const float IconCenterX = IconLeftX + IconRadius;
	const float TitleX = IconCenterX + IconRadius + IconGap;
	// Description text is left-aligned with the icon (spans the full card width below).
	const float MsgX = IconLeftX;

	std::vector<NotificationEntry> NotificationsCopy;
	{
		std::lock_guard<std::mutex> Lock(NotificationsMutex);
		NotificationsCopy.assign(NotificationsQueue.begin(), NotificationsQueue.end());
	}

	if (NotificationsCopy.empty())
		return;

	// Newest first — newest renders at the bottom, older stack upward.
	std::reverse(NotificationsCopy.begin(), NotificationsCopy.end());

	ImGui::SetNextWindowPos(ImVec2(0.0f, 0.0f), ImGuiCond_Always);
	ImGui::SetNextWindowSize(DisplaySize);
	ImGui::SetNextWindowBgAlpha(0.0f);
	ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));

	const ImGuiWindowFlags OverlayFlags =
		ImGuiWindowFlags_NoDecoration |
		ImGuiWindowFlags_NoMove |
		ImGuiWindowFlags_NoSavedSettings |
		ImGuiWindowFlags_NoNav |
		ImGuiWindowFlags_NoFocusOnAppearing |
		ImGuiWindowFlags_NoBringToFrontOnFocus |
		ImGuiWindowFlags_NoBackground;

	if (ImGui::Begin("##NotificationsOverlay", nullptr, OverlayFlags)) {
		ImDrawList* DrawList = ImGui::GetWindowDrawList();
		ImFont* Font = ImGui::GetFont();
		const float FontSize = ImGui::GetFontSize();
		const float TitleHeight = ImGui::GetTextLineHeight();
		const float MsgWrapWidth = (CardX + CardWidth - CardPadding) - MsgX;

		// Anchor to the bottom: place the newest card just above the bottom margin
		// and walk upward for older cards.
		float CursorBottom = DisplaySize.y - MarginBottom;

		for (const auto& Entry : NotificationsCopy) {
			float RemainingSec = Entry.DurationSec - Entry.ElapsedSec;
			if (RemainingSec < 0.0f)
				RemainingSec = 0.0f;

			// Fade in on appear, fade out before expiry
			float Alpha = 1.0f;
			if (Entry.ElapsedSec < FadeInDurationSec)
				Alpha = Entry.ElapsedSec / FadeInDurationSec;
			if (RemainingSec < FadeOutDurationSec)
				Alpha = (std::min)(Alpha, RemainingSec / FadeOutDurationSec);
			if (Alpha < 0.0f) Alpha = 0.0f;

			// ── Measure card height analytically (so we can stack from the bottom) ──
			const ImVec2 MsgSize = Font->CalcTextSizeA(FontSize, FLT_MAX, MsgWrapWidth, Entry.Message.c_str());
			const float ContentHeight =
				CardPadding +                       // top
				TitleHeight +                       // title row
				TitleToMsgGap +                     // gap below title
				MsgSize.y +                         // wrapped message
				CardPadding;                        // bottom
			const float CardHeight = ContentHeight + ProgressBarHeight;

			const ImVec2 CardMin(CardX, CursorBottom - CardHeight);
			const ImVec2 CardMax(CardX + CardWidth, CursorBottom);

			// Colors (pre-multiplied by alpha)
			const ImVec4 Accent4 = GetAccentColor(Entry.Type);
			const ImU32 AccentCol = ImGui::GetColorU32(ImVec4(Accent4.x, Accent4.y, Accent4.z, Alpha));
			const ImU32 BgCol     = ImGui::GetColorU32(ImVec4(0.12f, 0.12f, 0.15f, 0.97f * Alpha));
			const ImU32 BorderCol = ImGui::GetColorU32(ImVec4(1.0f, 1.0f, 1.0f, 0.05f * Alpha));
			const ImU32 ShadowCol = ImGui::GetColorU32(ImVec4(0.0f, 0.0f, 0.0f, 0.35f * Alpha));
			const ImU32 TitleCol  = ImGui::GetColorU32(ImVec4(0.95f, 0.95f, 0.97f, Alpha));
			const ImU32 MsgCol    = ImGui::GetColorU32(ImVec4(0.72f, 0.72f, 0.76f, Alpha));
			const ImU32 ProgBgCol = ImGui::GetColorU32(ImVec4(1.0f, 1.0f, 1.0f, 0.06f * Alpha));
			const float Progress  = Entry.DurationSec > 0.0f ? RemainingSec / Entry.DurationSec : 0.0f;

			// ── Soft drop shadow ──
			DrawList->AddRectFilled(
				ImVec2(CardMin.x + ShadowOffset, CardMin.y + ShadowOffset),
				ImVec2(CardMax.x + ShadowOffset, CardMax.y + ShadowOffset),
				ShadowCol, CardRounding);

			// ── Card background + subtle border ──
			DrawList->AddRectFilled(CardMin, CardMax, BgCol, CardRounding);
			DrawList->AddRect(CardMin, CardMax, BorderCol, CardRounding, 0, 1.0f);

			// ── Left accent strip (flush with the card's rounded left corners) ──
			DrawList->AddRectFilled(
				CardMin,
				ImVec2(CardMin.x + AccentBarWidth, CardMax.y),
				AccentCol, CardRounding, ImDrawFlags_RoundCornersLeft);

			// ── Type icon: tinted circle + crisp vector glyph ──
			const float IconCenterY = CardMin.y + CardPadding + TitleHeight * 0.5f;
			const ImVec2 IconCenter(IconCenterX, IconCenterY);
			const ImU32 IconBgCol = ImGui::GetColorU32(ImVec4(Accent4.x, Accent4.y, Accent4.z, 0.18f * Alpha));
			DrawList->AddCircleFilled(IconCenter, IconRadius, IconBgCol, 24);
			DrawTypeIcon(DrawList, IconCenter, IconRadius, Entry.Type, AccentCol);

			// ── Title: accent-colored severity label + the title text ──
			const float TitleY = CardMin.y + CardPadding;
			const char* TypeLabel = GetTypeLabel(Entry.Type);
			DrawList->AddText(ImVec2(TitleX, TitleY), AccentCol, TypeLabel);
			const float LabelWidth = Font->CalcTextSizeA(FontSize, FLT_MAX, 0.0f, TypeLabel).x;
			constexpr float LabelToTitleGap = 8.0f;
			DrawList->AddText(
				ImVec2(TitleX + LabelWidth + LabelToTitleGap, TitleY),
				TitleCol, Entry.Title.c_str());

			// ── Dismiss "×" button (top-right) ──
			const float CloseSize = 18.0f;
			const ImVec2 ClosePos(CardMax.x - CardPadding - CloseSize, CardMin.y + CardPadding - 1.0f);
			ImGui::SetCursorScreenPos(ClosePos);
			const std::string DismissId = "##D_" + std::to_string(Entry.Id);
			ImGui::InvisibleButton(DismissId.c_str(), ImVec2(CloseSize, CloseSize));
			const bool CloseHovered = ImGui::IsItemHovered();
			if (ImGui::IsItemClicked())
				RequestDismiss(Entry.Id);
			if (CloseHovered)
				DrawList->AddCircleFilled(
					ImVec2(ClosePos.x + CloseSize * 0.5f, ClosePos.y + CloseSize * 0.5f),
					CloseSize * 0.5f, ImGui::GetColorU32(ImVec4(1, 1, 1, 0.10f * Alpha)), 16);
			const ImU32 CloseCol = ImGui::GetColorU32(
				ImVec4(0.85f, 0.85f, 0.85f, (CloseHovered ? 1.0f : 0.5f) * Alpha));
			const ImVec2 XC(ClosePos.x + CloseSize * 0.5f, ClosePos.y + CloseSize * 0.5f);
			const float XR = 4.0f;
			DrawList->AddLine(ImVec2(XC.x - XR, XC.y - XR), ImVec2(XC.x + XR, XC.y + XR), CloseCol, 1.4f);
			DrawList->AddLine(ImVec2(XC.x - XR, XC.y + XR), ImVec2(XC.x + XR, XC.y - XR), CloseCol, 1.4f);

			// ── Message (manually wrapped, left-aligned with the icon) ──
			DrawList->AddText(
				Font, FontSize,
				ImVec2(MsgX, CardMin.y + CardPadding + TitleHeight + TitleToMsgGap),
				MsgCol, Entry.Message.c_str(), nullptr, MsgWrapWidth);

			// ── Bottom progress bar ──
			const float BarY0 = CardMax.y - ProgressBarHeight;
			DrawList->AddRectFilled(
				ImVec2(CardMin.x, BarY0), ImVec2(CardMax.x, CardMax.y),
				ProgBgCol, CardRounding, ImDrawFlags_RoundCornersBottom);
			DrawList->AddRectFilled(
				ImVec2(CardMin.x, BarY0), ImVec2(CardMin.x + CardWidth * Progress, CardMax.y),
				AccentCol, CardRounding, ImDrawFlags_RoundCornersBottom);

			// Move upward for the next (older) card
			CursorBottom = CardMin.y - CardGap;
		}
	}
	ImGui::End();
	ImGui::PopStyleVar();
}
