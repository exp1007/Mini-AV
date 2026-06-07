#include "NotificationsWindow.h"
#include "Notifications.h"

#include "imgui.h"
#include "imgui_impl_dx9.h"
#include "imgui_impl_win32.h"

#include <d3d9.h>
#include <windows.h>

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace {
	constexpr int WindowWidth = 460;

	LPDIRECT3D9 g_pD3D = nullptr;
	LPDIRECT3DDEVICE9 g_pd3dDevice = nullptr;
	HWND g_Hwnd = nullptr;
	HINSTANCE g_Instance = nullptr;
	ImGuiContext* g_Context = nullptr;
	ImGuiContext* g_MainContext = nullptr;
	bool g_DeviceLost = false;
	UINT g_ResizeWidth = 0;
	UINT g_ResizeHeight = 0;
	D3DPRESENT_PARAMETERS g_d3dpp = {};

	bool CreateDeviceD3D(HWND hWnd)
	{
		if ((g_pD3D = Direct3DCreate9(D3D_SDK_VERSION)) == nullptr)
			return false;

		ZeroMemory(&g_d3dpp, sizeof(g_d3dpp));
		g_d3dpp.Windowed = TRUE;
		g_d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
		g_d3dpp.BackBufferFormat = D3DFMT_A8R8G8B8;
		g_d3dpp.EnableAutoDepthStencil = TRUE;
		g_d3dpp.AutoDepthStencilFormat = D3DFMT_D16;
		g_d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_ONE;

		if (g_pD3D->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hWnd, D3DCREATE_HARDWARE_VERTEXPROCESSING, &g_d3dpp, &g_pd3dDevice) < 0)
			return false;

		return true;
	}

	void CleanupDeviceD3D()
	{
		if (g_pd3dDevice) {
			g_pd3dDevice->Release();
			g_pd3dDevice = nullptr;
		}
		if (g_pD3D) {
			g_pD3D->Release();
			g_pD3D = nullptr;
		}
	}

	void ResetDevice()
	{
		ImGui_ImplDX9_InvalidateDeviceObjects();
		const HRESULT hr = g_pd3dDevice->Reset(&g_d3dpp);
		if (hr == D3DERR_INVALIDCALL)
			IM_ASSERT(0);
		ImGui_ImplDX9_CreateDeviceObjects();
	}

	void UpdateWindowBounds()
	{
		RECT WorkArea{};
		SystemParametersInfo(SPI_GETWORKAREA, 0, &WorkArea, 0);

		const int Height = WorkArea.bottom - WorkArea.top;
		const int X = WorkArea.right - WindowWidth;
		const int Y = WorkArea.top;

		SetWindowPos(g_Hwnd, HWND_TOPMOST, X, Y, WindowWidth, Height, SWP_NOACTIVATE | SWP_NOOWNERZORDER);
	}

	LRESULT WINAPI NotificationsWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
	{
		ImGuiContext* PreviousContext = ImGui::GetCurrentContext();
		if (g_Context)
			ImGui::SetCurrentContext(g_Context);

		if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) {
			ImGui::SetCurrentContext(PreviousContext);
			return true;
		}

		switch (msg) {
		case WM_SIZE:
			if (wParam == SIZE_MINIMIZED) {
				ImGui::SetCurrentContext(PreviousContext);
				return 0;
			}
			g_ResizeWidth = LOWORD(lParam);
			g_ResizeHeight = HIWORD(lParam);
			ImGui::SetCurrentContext(PreviousContext);
			return 0;
		case WM_DESTROY:
			ImGui::SetCurrentContext(PreviousContext);
			return 0;
		default:
			break;
		}

		ImGui::SetCurrentContext(PreviousContext);
		return DefWindowProcW(hWnd, msg, wParam, lParam);
	}
}

bool UI::Components::NotificationsWindow::Initialize(void* Instance)
{
	g_Instance = static_cast<HINSTANCE>(Instance);
	g_MainContext = ImGui::GetCurrentContext();

	const wchar_t* ClassName = L"MiniAvNotifications";
	WNDCLASSEXW WindowClass{};
	WindowClass.cbSize = sizeof(WindowClass);
	WindowClass.style = CS_CLASSDC;
	WindowClass.lpfnWndProc = NotificationsWndProc;
	WindowClass.hInstance = g_Instance;
	WindowClass.lpszClassName = ClassName;
	RegisterClassExW(&WindowClass);

	RECT WorkArea{};
	SystemParametersInfo(SPI_GETWORKAREA, 0, &WorkArea, 0);
	const int Height = WorkArea.bottom - WorkArea.top;
	const int X = WorkArea.right - WindowWidth;
	const int Y = WorkArea.top;

	g_Hwnd = CreateWindowExW(
		WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
		ClassName,
		L"Mini-AV Notifications",
		WS_POPUP,
		X,
		Y,
		WindowWidth,
		Height,
		nullptr,
		nullptr,
		g_Instance,
		nullptr);

	if (!g_Hwnd)
		return false;

	if (!CreateDeviceD3D(g_Hwnd)) {
		DestroyWindow(g_Hwnd);
		g_Hwnd = nullptr;
		UnregisterClassW(ClassName, g_Instance);
		return false;
	}

	g_Context = ImGui::CreateContext();
	ImGui::SetCurrentContext(g_Context);

	ImGuiIO& Io = ImGui::GetIO();
	Io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
	ImGui::StyleColorsDark();

	ImGuiStyle& Style = ImGui::GetStyle();
	Style.WindowRounding = 5.0f;
	Style.ChildRounding = 5.0f;
	Style.FrameRounding = 5.0f;
	Style.WindowPadding = ImVec2(12.0f, 12.0f);
	Style.FramePadding = ImVec2(8.0f, 4.0f);
	Style.FrameBorderSize = 1.0f;

	ImGui_ImplWin32_Init(g_Hwnd);
	ImGui_ImplDX9_Init(g_pd3dDevice);
	ImGui_ImplWin32_EnableAlphaCompositing(g_Hwnd);
	Io.Fonts->AddFontFromFileTTF("c:\\Windows\\Fonts\\arial.ttf", 15.0f);

	ShowWindow(g_Hwnd, SW_HIDE);
	UpdateWindow(g_Hwnd);

	ImGui::SetCurrentContext(g_MainContext);
	return true;
}

void UI::Components::NotificationsWindow::Shutdown()
{
	if (!g_Context)
		return;

	ImGui::SetCurrentContext(g_Context);
	ImGui_ImplDX9_Shutdown();
	ImGui_ImplWin32_Shutdown();
	ImGui::DestroyContext(g_Context);
	g_Context = nullptr;

	CleanupDeviceD3D();

	if (g_Hwnd) {
		DestroyWindow(g_Hwnd);
		g_Hwnd = nullptr;
	}

	if (g_Instance)
		UnregisterClassW(L"MiniAvNotifications", g_Instance);
	ImGui::SetCurrentContext(g_MainContext);
}

void UI::Components::NotificationsWindow::RenderFrame(float DeltaSeconds)
{
	if (!g_Context || !g_Hwnd || !g_pd3dDevice)
		return;

	static bool WindowBoundsInitialized = false;

	if (!Notifications::HasActive()) {
		if (IsWindowVisible(g_Hwnd))
			ShowWindow(g_Hwnd, SW_HIDE);
		WindowBoundsInitialized = false;
		return;
	}
	if (!IsWindowVisible(g_Hwnd) || !WindowBoundsInitialized) {
		UpdateWindowBounds();
		WindowBoundsInitialized = true;
		ShowWindow(g_Hwnd, SW_SHOWNOACTIVATE);
	}

	if (g_DeviceLost) {
		const HRESULT hr = g_pd3dDevice->TestCooperativeLevel();
		if (hr == D3DERR_DEVICELOST) {
			Sleep(10);
			return;
		}
		if (hr == D3DERR_DEVICENOTRESET)
			ResetDevice();
		g_DeviceLost = false;
	}

	if (g_ResizeWidth != 0 && g_ResizeHeight != 0) {
		g_d3dpp.BackBufferWidth = g_ResizeWidth;
		g_d3dpp.BackBufferHeight = g_ResizeHeight;
		g_ResizeWidth = g_ResizeHeight = 0;
		ResetDevice();
	}

	ImGui::SetCurrentContext(g_Context);

	ImGui_ImplDX9_NewFrame();
	ImGui_ImplWin32_NewFrame();
	ImGui::NewFrame();

	Notifications::Update(DeltaSeconds);
	Notifications::Render();

	ImGui::EndFrame();

	g_pd3dDevice->SetRenderState(D3DRS_ZENABLE, FALSE);
	g_pd3dDevice->SetRenderState(D3DRS_ALPHABLENDENABLE, FALSE);
	g_pd3dDevice->SetRenderState(D3DRS_SCISSORTESTENABLE, FALSE);
	g_pd3dDevice->Clear(0, nullptr, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, D3DCOLOR_RGBA(0, 0, 0, 0), 1.0f, 0);

	if (g_pd3dDevice->BeginScene() >= 0) {
		ImGui::Render();
		ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
		g_pd3dDevice->EndScene();
	}

	const HRESULT PresentResult = g_pd3dDevice->Present(nullptr, nullptr, nullptr, nullptr);
	if (PresentResult == D3DERR_DEVICELOST)
		g_DeviceLost = true;

	ImGui::SetCurrentContext(g_MainContext);
}
