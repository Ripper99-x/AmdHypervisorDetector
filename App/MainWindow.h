#pragma once

#include "DetectionEngine.h"

#include <Windows.h>
#include <d2d1.h>
#include <dwrite.h>
#include <wrl/client.h>

#include <atomic>
#include <cstddef>
#include <mutex>
#include <string>
#include <thread>

namespace ahd {

class MainWindow final {
public:
    MainWindow();
    ~MainWindow();

    bool Create(HINSTANCE instance, int showCommand);
    HWND Handle() const noexcept { return window_; }

private:
    static constexpr UINT kMessageResultsReady = WM_APP + 1;
    static constexpr UINT kMessageProgress = WM_APP + 2;
    static constexpr int kRunAllButtonId = 1001;
    static constexpr int kRunSelectedButtonId = 1002;
    static constexpr int kSaveReportButtonId = 1003;

    static LRESULT CALLBACK WindowProcedure(HWND window, UINT message, WPARAM wParam, LPARAM lParam);
    LRESULT HandleMessage(UINT message, WPARAM wParam, LPARAM lParam);

    bool InitializeGraphics();
    bool CreateDeviceResources();
    void DiscardDeviceResources();
    void CreateChildControls();
    void RecreateButtonFont();
    void LayoutChildControls();
    void UpdateControlState();
    void Paint();
    void DrawDashboard(const DetectionSnapshot& snapshot);
    void DrawTestList(const DetectionSnapshot& snapshot, const D2D1_RECT_F& bounds);
    void DrawDetails(const DetectionSnapshot& snapshot, const D2D1_RECT_F& bounds);
    void DrawHistogram(const TestResult& result, const D2D1_RECT_F& bounds);

    void DrawTextBlock(
        const std::wstring& text,
        const D2D1_RECT_F& bounds,
        IDWriteTextFormat* format,
        const D2D1_COLOR_F& color);
    [[nodiscard]] float MeasureTextHeight(
        const std::wstring& text,
        float width,
        IDWriteTextFormat* format,
        float minimum = 0.0f) const;
    void FillRounded(const D2D1_RECT_F& bounds, float radius, const D2D1_COLOR_F& color);
    void StrokeRounded(const D2D1_RECT_F& bounds, float radius, const D2D1_COLOR_F& color, float width = 1.0f);

    void StartRunAll();
    void StartRunSelected();
    void StartRunOne(std::size_t index);
    void SaveReportAs();
    void SelectAt(float x, float y);
    void HandleMouseWheel(short delta, float x);
    DetectionSnapshot SnapshotCopy() const;

    D2D1_COLOR_F VerdictColor(Verdict verdict) const noexcept;
    float CurrentDpiScale() const noexcept;
    int DipToPixel(float value) const noexcept;

    HWND window_{};
    HWND runAllButton_{};
    HWND runSelectedButton_{};
    HWND saveReportButton_{};
    HFONT buttonFont_{};
    HINSTANCE instance_{};

    Microsoft::WRL::ComPtr<ID2D1Factory> d2dFactory_;
    Microsoft::WRL::ComPtr<IDWriteFactory> writeFactory_;
    Microsoft::WRL::ComPtr<ID2D1HwndRenderTarget> renderTarget_;
    Microsoft::WRL::ComPtr<ID2D1SolidColorBrush> brush_;
    Microsoft::WRL::ComPtr<IDWriteTextFormat> titleFormat_;
    Microsoft::WRL::ComPtr<IDWriteTextFormat> headingFormat_;
    Microsoft::WRL::ComPtr<IDWriteTextFormat> bodyFormat_;
    Microsoft::WRL::ComPtr<IDWriteTextFormat> smallFormat_;
    Microsoft::WRL::ComPtr<IDWriteTextFormat> statusFormat_;
    Microsoft::WRL::ComPtr<IDWriteTextFormat> metricFormat_;

    DetectionEngine engine_;
    mutable std::mutex snapshotMutex_;
    DetectionSnapshot snapshot_;
    std::thread worker_;
    std::atomic_bool running_{};
    std::atomic_bool closing_{};
    std::atomic_size_t progressCompleted_{};
    std::atomic_size_t progressTotal_{};
    std::size_t selectedIndex_{};
    float listScroll_{};
    float detailScroll_{};
    float detailContentHeight_{};
    D2D1_RECT_F listBounds_{};
    D2D1_RECT_F detailBounds_{};
    std::wstring activityText_{L"Ready to sample"};
};

} // namespace ahd
