#include "MainWindow.h"

#include <Windows.h>
#include <commctrl.h>
#include <objbase.h>

int WINAPI wWinMain(
    _In_ HINSTANCE instance,
    _In_opt_ HINSTANCE previousInstance,
    _In_ PWSTR commandLine,
    _In_ int showCommand) {
    UNREFERENCED_PARAMETER(previousInstance);
    UNREFERENCED_PARAMETER(commandLine);

    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&controls);

    const HRESULT comStatus = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    ahd::MainWindow window;
    if (!window.Create(instance, showCommand)) {
        MessageBoxW(nullptr, L"Could not create the detector window.", L"AMD Hypervisor Detector", MB_OK | MB_ICONERROR);
        if (SUCCEEDED(comStatus)) CoUninitialize();
        return 1;
    }

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    if (SUCCEEDED(comStatus)) CoUninitialize();
    return static_cast<int>(message.wParam);
}

