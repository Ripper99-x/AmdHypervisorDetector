#include "MainWindow.h"

#include "PlatformUtils.h"
#include "ReportWriter.h"
#include "Statistics.h"

#include <Windows.h>
#include <commdlg.h>
#include <d2d1helper.h>
#include <dwmapi.h>
#include <uxtheme.h>
#include <windowsx.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <utility>
#include <vector>

namespace ahd {
namespace {

constexpr wchar_t kWindowClassName[] = L"AmdHypervisorDetector.MainWindow";
constexpr float kTopContent = 181.0f;
constexpr float kFooterHeight = 66.0f;
constexpr float kOuterMargin = 22.0f;
constexpr float kListWidth = 420.0f;
constexpr float kColumnGap = 16.0f;
constexpr float kCardHeight = 96.0f;
constexpr float kCardGap = 9.0f;
constexpr float kCardStride = kCardHeight + kCardGap;

const D2D1_COLOR_F kBackground = D2D1::ColorF(0x0b1018);
const D2D1_COLOR_F kPanel = D2D1::ColorF(0x121a26);
const D2D1_COLOR_F kPanelRaised = D2D1::ColorF(0x182231);
const D2D1_COLOR_F kBorder = D2D1::ColorF(0x2a3748);
const D2D1_COLOR_F kText = D2D1::ColorF(0xe8eef7);
const D2D1_COLOR_F kMuted = D2D1::ColorF(0x8ea0b7);
const D2D1_COLOR_F kAccent = D2D1::ColorF(0x6ea8fe);
const D2D1_COLOR_F kPass = D2D1::ColorF(0x4dd4a4);
const D2D1_COLOR_F kSuspicious = D2D1::ColorF(0xf4bb55);
const D2D1_COLOR_F kDetected = D2D1::ColorF(0xff6577);
const D2D1_COLOR_F kNeutral = D2D1::ColorF(0x718198);

bool PointInRect(const D2D1_RECT_F& rectangle, const float x, const float y) {
    return x >= rectangle.left && x <= rectangle.right &&
           y >= rectangle.top && y <= rectangle.bottom;
}

std::wstring CompactDuration(const TestResult& result) {
    if (result.verdict == Verdict::Running) return L"sampling";
    if (result.duration.count() == 0) {
        return result.verdict == Verdict::Pass || result.verdict == Verdict::Suspicious ||
               result.verdict == Verdict::Detected
            ? L"<1 ms"
            : L"—";
    }
    if (result.duration.count() < 1000) {
        return std::to_wstring(result.duration.count()) + L" ms";
    }
    return FormatFixed(static_cast<double>(result.duration.count()) / 1000.0, 1) + L" s";
}

std::wstring ListCardContext(const TestResult& result) {
    if (!result.anomalyScore.has_value() || !std::isfinite(*result.anomalyScore)) {
        return result.metadata.category;
    }
    return result.metadata.category + L"  •  score " +
        FormatFixed(std::clamp(*result.anomalyScore, 0.0, 100.0), 0);
}

struct VerdictCounts {
    std::size_t pass{};
    std::size_t suspicious{};
    std::size_t detected{};
    std::size_t unavailable{};
    std::size_t error{};
    std::size_t running{};
};

VerdictCounts CountVerdicts(const DetectionSnapshot& snapshot) {
    VerdictCounts counts{};
    for (const auto& result : snapshot.results) {
        switch (result.verdict) {
        case Verdict::Pass: ++counts.pass; break;
        case Verdict::Suspicious: ++counts.suspicious; break;
        case Verdict::Detected: ++counts.detected; break;
        case Verdict::Unavailable: ++counts.unavailable; break;
        case Verdict::Error: ++counts.error; break;
        case Verdict::Running: ++counts.running; break;
        }
    }
    return counts;
}

std::wstring TimingMetricSummary(const TimingStatistics& statistics) {
    const double outlierRate = statistics.sampleCount == 0
        ? 0.0
        : static_cast<double>(statistics.outlierCount) * 100.0 /
          static_cast<double>(statistics.sampleCount);
    return L"n " + std::to_wstring(statistics.sampleCount) +
        L"   median " + FormatCycles(statistics.median) +
        L"   average " + FormatCycles(statistics.average) +
        L"   P95 " + FormatCycles(statistics.p95) +
        L"   max " + FormatCycles(static_cast<double>(statistics.maximum)) + L"\n" +
        L"Q1 " + FormatCycles(statistics.q1) +
        L"   Q3 " + FormatCycles(statistics.q3) +
        L"   std dev " + FormatFixed(statistics.standardDeviation, 1) +
        L"   variance " + FormatFixed(statistics.variance, 1) +
        L"   outliers " + std::to_wstring(statistics.outlierCount) +
        L" (" + FormatFixed(outlierRate, 1) + L"%)";
}

std::wstring RawSamplePreview(
    const std::wstring& seriesName,
    const std::vector<std::uint64_t>& samples,
    const std::size_t maximumShown) {
    std::wostringstream preview;
    const std::size_t shown = std::min(maximumShown, samples.size());
    preview << seriesName << L" — " << samples.size() << L" samples; showing first " << shown;
    for (std::size_t index = 0; index < shown; ++index) {
        if (index % 12 == 0) {
            preview << L"\n[" << index << L"] ";
        } else {
            preview << L", ";
        }
        preview << samples[index];
    }
    if (shown < samples.size()) preview << L"\n… remaining samples are preserved in the JSON report.";
    return preview.str();
}

} // namespace

MainWindow::MainWindow() {
    const auto metadata = engine_.Metadata();
    snapshot_.results.reserve(metadata.size());
    for (const auto& item : metadata) {
        TestResult result{};
        result.metadata = item;
        result.verdict = Verdict::Unavailable;
        result.summary = L"Waiting for the first run.";
        result.explanation = L"Select Run all to collect this observation.";
        snapshot_.results.push_back(std::move(result));
    }
}

MainWindow::~MainWindow() {
    closing_.store(true);
    if (worker_.joinable()) {
        worker_.join();
    }
    if (buttonFont_ != nullptr) {
        DeleteObject(buttonFont_);
    }
}

bool MainWindow::InitializeGraphics() {
    if (FAILED(D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, d2dFactory_.ReleaseAndGetAddressOf()))) {
        return false;
    }
    if (FAILED(DWriteCreateFactory(
            DWRITE_FACTORY_TYPE_SHARED,
            __uuidof(IDWriteFactory),
            reinterpret_cast<IUnknown**>(writeFactory_.ReleaseAndGetAddressOf())))) {
        return false;
    }

    const auto createFormat = [&](const float size, const DWRITE_FONT_WEIGHT weight,
                                  Microsoft::WRL::ComPtr<IDWriteTextFormat>& output) {
        const HRESULT status = writeFactory_->CreateTextFormat(
            L"Segoe UI Variable",
            nullptr,
            weight,
            DWRITE_FONT_STYLE_NORMAL,
            DWRITE_FONT_STRETCH_NORMAL,
            size,
            L"en-us",
            output.ReleaseAndGetAddressOf());
        if (SUCCEEDED(status)) {
            output->SetWordWrapping(DWRITE_WORD_WRAPPING_WRAP);
        }
        return status;
    };

    return SUCCEEDED(createFormat(26.0f, DWRITE_FONT_WEIGHT_SEMI_BOLD, titleFormat_)) &&
           SUCCEEDED(createFormat(19.0f, DWRITE_FONT_WEIGHT_SEMI_BOLD, headingFormat_)) &&
           SUCCEEDED(createFormat(13.0f, DWRITE_FONT_WEIGHT_NORMAL, bodyFormat_)) &&
           SUCCEEDED(createFormat(11.0f, DWRITE_FONT_WEIGHT_NORMAL, smallFormat_)) &&
           SUCCEEDED(createFormat(11.5f, DWRITE_FONT_WEIGHT_SEMI_BOLD, statusFormat_)) &&
           SUCCEEDED(createFormat(21.0f, DWRITE_FONT_WEIGHT_SEMI_BOLD, metricFormat_));
}

bool MainWindow::Create(HINSTANCE instance, const int showCommand) {
    instance_ = instance;
    if (!InitializeGraphics()) {
        return false;
    }

    WNDCLASSEXW windowClass{};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.style = CS_HREDRAW | CS_VREDRAW;
    windowClass.lpfnWndProc = WindowProcedure;
    windowClass.hInstance = instance;
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    windowClass.hbrBackground = nullptr;
    windowClass.lpszClassName = kWindowClassName;
    if (RegisterClassExW(&windowClass) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return false;
    }

    window_ = CreateWindowExW(
        0,
        kWindowClassName,
        L"AMD Hypervisor Detector",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        1220,
        820,
        nullptr,
        nullptr,
        instance,
        this);
    if (window_ == nullptr) {
        return false;
    }

    BOOL darkMode = TRUE;
    DwmSetWindowAttribute(window_, 20, &darkMode, sizeof(darkMode));
    ShowWindow(window_, showCommand);
    UpdateWindow(window_);
    PostMessageW(window_, WM_COMMAND, MAKEWPARAM(kRunAllButtonId, BN_CLICKED),
                 reinterpret_cast<LPARAM>(runAllButton_));
    return true;
}

LRESULT CALLBACK MainWindow::WindowProcedure(
    HWND window,
    const UINT message,
    const WPARAM wParam,
    const LPARAM lParam) {
    MainWindow* self = reinterpret_cast<MainWindow*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
        self = static_cast<MainWindow*>(create->lpCreateParams);
        self->window_ = window;
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    }
    if (self != nullptr) {
        return self->HandleMessage(message, wParam, lParam);
    }
    return DefWindowProcW(window, message, wParam, lParam);
}

LRESULT MainWindow::HandleMessage(const UINT message, const WPARAM wParam, const LPARAM lParam) {
    switch (message) {
    case WM_CREATE:
        CreateChildControls();
        return 0;
    case WM_SIZE:
        if (renderTarget_ != nullptr) {
            renderTarget_->Resize(D2D1::SizeU(LOWORD(lParam), HIWORD(lParam)));
        }
        LayoutChildControls();
        InvalidateRect(window_, nullptr, FALSE);
        return 0;
    case WM_DPICHANGED: {
        const auto* suggested = reinterpret_cast<const RECT*>(lParam);
        SetWindowPos(window_, nullptr, suggested->left, suggested->top,
                     suggested->right - suggested->left, suggested->bottom - suggested->top,
                     SWP_NOZORDER | SWP_NOACTIVATE);
        LayoutChildControls();
        RecreateButtonFont();
        DiscardDeviceResources();
        return 0;
    }
    case WM_GETMINMAXINFO: {
        auto* information = reinterpret_cast<MINMAXINFO*>(lParam);
        information->ptMinTrackSize.x = DipToPixel(900.0f);
        information->ptMinTrackSize.y = DipToPixel(620.0f);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT:
        Paint();
        return 0;
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case kRunAllButtonId:
            if (HIWORD(wParam) == BN_CLICKED) StartRunAll();
            return 0;
        case kRunSelectedButtonId:
            if (HIWORD(wParam) == BN_CLICKED) StartRunSelected();
            return 0;
        case kSaveReportButtonId:
            if (HIWORD(wParam) == BN_CLICKED) SaveReportAs();
            return 0;
        default:
            break;
        }
        break;
    case WM_LBUTTONDOWN: {
        const float scale = CurrentDpiScale();
        const float x = static_cast<float>(GET_X_LPARAM(lParam)) / scale;
        const float y = static_cast<float>(GET_Y_LPARAM(lParam)) / scale;
        SelectAt(x, y);
        return 0;
    }
    case WM_MOUSEWHEEL: {
        POINT point{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
        ScreenToClient(window_, &point);
        HandleMouseWheel(GET_WHEEL_DELTA_WPARAM(wParam),
                         static_cast<float>(point.x) / CurrentDpiScale());
        return 0;
    }
    case kMessageProgress: {
        progressCompleted_.store(static_cast<std::size_t>(wParam));
        progressTotal_.store(static_cast<std::size_t>(lParam));
        activityText_ = L"Sampling " + std::to_wstring(wParam) + L" / " + std::to_wstring(lParam);
        InvalidateRect(window_, nullptr, FALSE);
        return 0;
    }
    case kMessageResultsReady: {
        if (worker_.joinable()) worker_.join();
        const auto snapshot = SnapshotCopy();
        activityText_ = snapshot.reportPath.empty()
            ? (snapshot.reportError.empty()
                ? L"Run complete; automatic report could not be saved"
                : L"Run complete; report error: " + snapshot.reportError)
            : L"Report: " + snapshot.reportPath;
        UpdateControlState();
        InvalidateRect(window_, nullptr, FALSE);
        return 0;
    }
    case WM_CLOSE:
        closing_.store(true);
        DestroyWindow(window_);
        return 0;
    case WM_DESTROY:
        if (worker_.joinable()) worker_.join();
        PostQuitMessage(0);
        return 0;
    default:
        break;
    }
    return DefWindowProcW(window_, message, wParam, lParam);
}

void MainWindow::CreateChildControls() {
    RecreateButtonFont();

    const auto createButton = [&](const wchar_t* text, const int identifier) {
        HWND button = CreateWindowExW(
            0, L"BUTTON", text,
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            0, 0, 120, 34,
            window_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(identifier)), instance_, nullptr);
        SendMessageW(button, WM_SETFONT, reinterpret_cast<WPARAM>(buttonFont_), TRUE);
        SetWindowTheme(button, L"DarkMode_Explorer", nullptr);
        return button;
    };

    runAllButton_ = createButton(L"Run all", kRunAllButtonId);
    runSelectedButton_ = createButton(L"Rerun selected", kRunSelectedButtonId);
    saveReportButton_ = createButton(L"Save report", kSaveReportButtonId);
    LayoutChildControls();
    UpdateControlState();
}

void MainWindow::RecreateButtonFont() {
    if (buttonFont_ != nullptr) {
        DeleteObject(buttonFont_);
        buttonFont_ = nullptr;
    }
    buttonFont_ = CreateFontW(
        -DipToPixel(13.0f), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    if (runAllButton_ != nullptr) {
        SendMessageW(runAllButton_, WM_SETFONT, reinterpret_cast<WPARAM>(buttonFont_), TRUE);
        SendMessageW(runSelectedButton_, WM_SETFONT, reinterpret_cast<WPARAM>(buttonFont_), TRUE);
        SendMessageW(saveReportButton_, WM_SETFONT, reinterpret_cast<WPARAM>(buttonFont_), TRUE);
    }
}

void MainWindow::LayoutChildControls() {
    if (window_ == nullptr) return;
    const int y = DipToPixel(79.0f);
    const int height = DipToPixel(34.0f);
    MoveWindow(runAllButton_, DipToPixel(kOuterMargin), y, DipToPixel(112.0f), height, TRUE);
    MoveWindow(runSelectedButton_, DipToPixel(kOuterMargin + 122.0f), y, DipToPixel(136.0f), height, TRUE);
    MoveWindow(saveReportButton_, DipToPixel(kOuterMargin + 268.0f), y, DipToPixel(126.0f), height, TRUE);
}

void MainWindow::UpdateControlState() {
    const BOOL enabled = running_.load() ? FALSE : TRUE;
    EnableWindow(runAllButton_, enabled);
    EnableWindow(runSelectedButton_, enabled);
    EnableWindow(saveReportButton_, enabled);
}

bool MainWindow::CreateDeviceResources() {
    if (renderTarget_ != nullptr) return true;
    RECT client{};
    GetClientRect(window_, &client);
    const auto size = D2D1::SizeU(
        static_cast<UINT32>(std::max(1L, client.right - client.left)),
        static_cast<UINT32>(std::max(1L, client.bottom - client.top)));
    if (FAILED(d2dFactory_->CreateHwndRenderTarget(
            D2D1::RenderTargetProperties(),
            D2D1::HwndRenderTargetProperties(window_, size),
            renderTarget_.ReleaseAndGetAddressOf()))) {
        return false;
    }
    const float dpi = static_cast<float>(GetDpiForWindow(window_));
    renderTarget_->SetDpi(dpi, dpi);
    return SUCCEEDED(renderTarget_->CreateSolidColorBrush(kText, brush_.ReleaseAndGetAddressOf()));
}

void MainWindow::DiscardDeviceResources() {
    brush_.Reset();
    renderTarget_.Reset();
}

void MainWindow::DrawTextBlock(
    const std::wstring& text,
    const D2D1_RECT_F& bounds,
    IDWriteTextFormat* format,
    const D2D1_COLOR_F& color) {
    if (text.empty() || bounds.right <= bounds.left || bounds.bottom <= bounds.top) return;
    brush_->SetColor(color);
    renderTarget_->DrawTextW(
        text.c_str(), static_cast<UINT32>(text.size()), format, bounds, brush_.Get(),
        D2D1_DRAW_TEXT_OPTIONS_CLIP, DWRITE_MEASURING_MODE_NATURAL);
}

float MainWindow::MeasureTextHeight(
    const std::wstring& text,
    const float width,
    IDWriteTextFormat* format,
    const float minimum) const {
    if (text.empty() || width <= 0.0f || format == nullptr || writeFactory_ == nullptr) {
        return minimum;
    }
    Microsoft::WRL::ComPtr<IDWriteTextLayout> layout;
    if (FAILED(writeFactory_->CreateTextLayout(
            text.c_str(), static_cast<UINT32>(text.size()), format,
            width, 10000.0f, layout.ReleaseAndGetAddressOf()))) {
        return minimum;
    }
    DWRITE_TEXT_METRICS metrics{};
    if (FAILED(layout->GetMetrics(&metrics))) return minimum;
    return std::max(minimum, std::ceil(metrics.height));
}

void MainWindow::FillRounded(
    const D2D1_RECT_F& bounds,
    const float radius,
    const D2D1_COLOR_F& color) {
    brush_->SetColor(color);
    renderTarget_->FillRoundedRectangle(D2D1::RoundedRect(bounds, radius, radius), brush_.Get());
}

void MainWindow::StrokeRounded(
    const D2D1_RECT_F& bounds,
    const float radius,
    const D2D1_COLOR_F& color,
    const float width) {
    brush_->SetColor(color);
    renderTarget_->DrawRoundedRectangle(D2D1::RoundedRect(bounds, radius, radius), brush_.Get(), width);
}

void MainWindow::Paint() {
    PAINTSTRUCT paint{};
    BeginPaint(window_, &paint);
    if (CreateDeviceResources()) {
        renderTarget_->BeginDraw();
        renderTarget_->Clear(kBackground);
        DrawDashboard(SnapshotCopy());
        const HRESULT status = renderTarget_->EndDraw();
        if (status == D2DERR_RECREATE_TARGET) {
            DiscardDeviceResources();
        }
    }
    EndPaint(window_, &paint);
}

D2D1_COLOR_F MainWindow::VerdictColor(const Verdict verdict) const noexcept {
    switch (verdict) {
    case Verdict::Pass: return kPass;
    case Verdict::Suspicious: return kSuspicious;
    case Verdict::Detected: return kDetected;
    case Verdict::Running: return kAccent;
    default: return kNeutral;
    }
}

void MainWindow::DrawDashboard(const DetectionSnapshot& snapshot) {
    const auto size = renderTarget_->GetSize();
    const VerdictCounts counts = CountVerdicts(snapshot);
    DrawTextBlock(L"AMD Hypervisor Detector",
                  D2D1::RectF(kOuterMargin, 17.0f, size.width - 310.0f, 52.0f),
                  titleFormat_.Get(), kText);

    std::wstring platform = snapshot.system.cpuBrand.empty()
        ? L"Windows x64 / AMD-only research instrumentation"
        : Utf8ToWide(snapshot.system.cpuBrand) + L"  •  " + snapshot.system.windowsVersion;
    DrawTextBlock(platform,
                  D2D1::RectF(kOuterMargin, 52.0f, size.width - 310.0f, 72.0f),
                  smallFormat_.Get(), kMuted);

    const D2D1_RECT_F summaryCard = D2D1::RectF(size.width - 294.0f, 16.0f, size.width - kOuterMargin, 108.0f);
    FillRounded(summaryCard, 12.0f, kPanelRaised);
    const auto statusColor = VerdictColor(snapshot.overallVerdict);
    FillRounded(D2D1::RectF(summaryCard.left + 16.0f, summaryCard.top + 14.0f,
                            summaryCard.left + 124.0f, summaryCard.top + 40.0f),
                13.0f, D2D1::ColorF(statusColor.r, statusColor.g, statusColor.b, 0.18f));
    DrawTextBlock(VerdictLabel(snapshot.overallVerdict),
                  D2D1::RectF(summaryCard.left + 25.0f, summaryCard.top + 19.0f,
                              summaryCard.left + 120.0f, summaryCard.top + 37.0f),
                  statusFormat_.Get(), statusColor);
    DrawTextBlock(std::to_wstring(snapshot.confidenceScore) + L"%",
                  D2D1::RectF(summaryCard.right - 82.0f, summaryCard.top + 9.0f,
                              summaryCard.right - 14.0f, summaryCard.top + 42.0f),
                  metricFormat_.Get(), statusColor);
    DrawTextBlock(L"evidence confidence",
                  D2D1::RectF(summaryCard.left + 17.0f, summaryCard.top + 52.0f,
                              summaryCard.right - 14.0f, summaryCard.bottom - 8.0f),
                  smallFormat_.Get(), kMuted);

    const std::size_t total = progressTotal_.load();
    const std::size_t completed = progressCompleted_.load();
    const float progress = total == 0 ? 0.0f
        : std::clamp(static_cast<float>(completed) / static_cast<float>(total), 0.0f, 1.0f);
    FillRounded(D2D1::RectF(kOuterMargin, 119.0f, size.width - kOuterMargin, 123.0f), 2.0f, kPanelRaised);
    if (progress > 0.0f) {
        FillRounded(D2D1::RectF(kOuterMargin, 119.0f,
                                kOuterMargin + (size.width - 2.0f * kOuterMargin) * progress, 123.0f),
                    2.0f, kAccent);
    }

    const D2D1_RECT_F overview = D2D1::RectF(
        kOuterMargin, 130.0f, size.width - kOuterMargin, 171.0f);
    FillRounded(overview, 8.0f, kPanelRaised);
    const float countTop = overview.top + 7.0f;
    float countLeft = overview.left + 12.0f;
    const auto drawCount = [&](const std::wstring& label, const std::size_t count,
                               const D2D1_COLOR_F& color, const float width) {
        DrawTextBlock(label + L" " + std::to_wstring(count),
                      D2D1::RectF(countLeft, countTop, countLeft + width, countTop + 17.0f),
                      statusFormat_.Get(), color);
        countLeft += width;
    };
    drawCount(L"PASS", counts.pass, kPass, 82.0f);
    drawCount(L"SUSPICIOUS", counts.suspicious, kSuspicious, 124.0f);
    drawCount(L"DETECTED", counts.detected, kDetected, 104.0f);
    drawCount(L"UNAVAILABLE", counts.unavailable, kNeutral, 130.0f);
    drawCount(L"ERROR", counts.error, kDetected, 82.0f);
    if (counts.running != 0) drawCount(L"RUNNING", counts.running, kAccent, 92.0f);

    const std::wstring confidenceDetail = snapshot.confidenceExplanation.empty()
        ? L"Run all checks to collect evidence and calculate the confidence index."
        : L"Confidence: " + snapshot.confidenceExplanation;
    DrawTextBlock(confidenceDetail,
                  D2D1::RectF(overview.left + 12.0f, overview.top + 23.0f,
                              overview.right - 12.0f, overview.bottom - 4.0f),
                  smallFormat_.Get(), kMuted);

    listBounds_ = D2D1::RectF(
        kOuterMargin,
        kTopContent,
        std::min(kOuterMargin + kListWidth, size.width * 0.44f),
        size.height - kFooterHeight - 8.0f);
    detailBounds_ = D2D1::RectF(
        listBounds_.right + kColumnGap,
        kTopContent,
        size.width - kOuterMargin,
        size.height - kFooterHeight - 8.0f);
    DrawTestList(snapshot, listBounds_);
    DrawDetails(snapshot, detailBounds_);

    const float footerTop = size.height - kFooterHeight;
    FillRounded(D2D1::RectF(kOuterMargin, footerTop + 3.0f,
                            size.width - kOuterMargin, size.height - 5.0f),
                7.0f, kPanel);
    const std::wstring footerStatus = running_.load()
        ? activityText_
        : (!snapshot.reportPath.empty()
            ? L"Run complete  •  automatic JSON report saved"
            : (!snapshot.reportError.empty()
                ? L"Run complete  •  report save failed"
                : activityText_));
    DrawTextBlock(footerStatus,
                  D2D1::RectF(kOuterMargin + 11.0f, footerTop + 9.0f,
                              size.width - kOuterMargin - 11.0f, footerTop + 27.0f),
                  statusFormat_.Get(), snapshot.reportError.empty() ? kMuted : kDetected);
    std::wstring reportDetail;
    if (!snapshot.reportPath.empty()) {
        reportDetail = L"Report path: " + snapshot.reportPath;
    } else if (!snapshot.reportError.empty()) {
        reportDetail = L"Report error: " + snapshot.reportError;
    } else {
        reportDetail = L"No completed report is available yet.";
    }
    DrawTextBlock(reportDetail,
                  D2D1::RectF(kOuterMargin + 11.0f, footerTop + 31.0f,
                              size.width - kOuterMargin - 11.0f, size.height - 9.0f),
                  smallFormat_.Get(), snapshot.reportError.empty() ? kText : kDetected);
}

void MainWindow::DrawTestList(const DetectionSnapshot& snapshot, const D2D1_RECT_F& bounds) {
    FillRounded(bounds, 12.0f, kPanel);
    renderTarget_->PushAxisAlignedClip(bounds, D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
    const float left = bounds.left + 10.0f;
    const float right = bounds.right - 10.0f;
    float y = bounds.top + 10.0f - listScroll_;

    for (std::size_t index = 0; index < snapshot.results.size(); ++index) {
        const auto& result = snapshot.results[index];
        const D2D1_RECT_F card = D2D1::RectF(left, y, right, y + kCardHeight);
        if (card.bottom >= bounds.top && card.top <= bounds.bottom) {
            FillRounded(card, 9.0f, index == selectedIndex_ ? kPanelRaised : D2D1::ColorF(0x141d29));
            if (index == selectedIndex_) StrokeRounded(card, 9.0f, kAccent, 1.4f);

            const auto color = VerdictColor(result.verdict);
            FillRounded(D2D1::RectF(card.left + 11.0f, card.top + 11.0f,
                                    card.left + 101.0f, card.top + 32.0f),
                        10.0f, D2D1::ColorF(color.r, color.g, color.b, 0.16f));
            DrawTextBlock(VerdictLabel(result.verdict),
                          D2D1::RectF(card.left + 18.0f, card.top + 14.0f,
                                      card.left + 99.0f, card.top + 30.0f),
                          statusFormat_.Get(), color);
            DrawTextBlock(ListCardContext(result),
                          D2D1::RectF(card.left + 112.0f, card.top + 13.0f,
                                      card.right - 112.0f, card.top + 31.0f),
                          smallFormat_.Get(), kMuted);
            DrawTextBlock(CompactDuration(result),
                          D2D1::RectF(card.right - 108.0f, card.top + 13.0f,
                                      card.right - 54.0f, card.top + 31.0f),
                          smallFormat_.Get(), kMuted);
            DrawTextBlock(result.metadata.title,
                          D2D1::RectF(card.left + 12.0f, card.top + 39.0f,
                                      card.right - 12.0f, card.top + 60.0f),
                          bodyFormat_.Get(), kText);
            DrawTextBlock(result.summary,
                          D2D1::RectF(card.left + 12.0f, card.top + 64.0f,
                                      card.right - 12.0f, card.bottom - 6.0f),
                          smallFormat_.Get(), kMuted);

            const D2D1_RECT_F runButton = D2D1::RectF(card.right - 48.0f, card.top + 10.0f,
                                                      card.right - 10.0f, card.top + 34.0f);
            StrokeRounded(runButton, 7.0f, running_.load() ? kNeutral : kAccent);
            DrawTextBlock(L"Run", D2D1::RectF(runButton.left + 7.0f, runButton.top + 5.0f,
                                               runButton.right, runButton.bottom),
                          smallFormat_.Get(), running_.load() ? kNeutral : kAccent);
        }
        y += kCardStride;
    }
    renderTarget_->PopAxisAlignedClip();

    const float viewport = bounds.bottom - bounds.top;
    const float content = 20.0f + static_cast<float>(snapshot.results.size()) * kCardStride;
    if (content > viewport) {
        const float trackTop = bounds.top + 10.0f;
        const float trackHeight = viewport - 20.0f;
        const float thumbHeight = std::max(32.0f, trackHeight * viewport / content);
        const float maximum = content - viewport;
        const float thumbTop = trackTop + (trackHeight - thumbHeight) *
            (maximum > 0.0f ? listScroll_ / maximum : 0.0f);
        FillRounded(D2D1::RectF(bounds.right - 5.0f, trackTop, bounds.right - 2.0f,
                                trackTop + trackHeight), 1.5f, kBorder);
        FillRounded(D2D1::RectF(bounds.right - 6.0f, thumbTop, bounds.right - 1.0f,
                                thumbTop + thumbHeight), 2.5f, kAccent);
    }
}

void MainWindow::DrawHistogram(const TestResult& result, const D2D1_RECT_F& bounds) {
    FillRounded(bounds, 8.0f, D2D1::ColorF(0x0e1621));
    if (result.rawSamples.empty()) {
        DrawTextBlock(L"No raw timing samples", bounds, smallFormat_.Get(), kMuted);
        return;
    }

    constexpr std::size_t bucketCount = 32;
    std::array<std::size_t, bucketCount> buckets{};
    const auto minimum = *std::min_element(result.rawSamples.begin(), result.rawSamples.end());
    const double p95 = result.timing.has_value()
        ? result.timing->p95
        : static_cast<double>(*std::max_element(result.rawSamples.begin(), result.rawSamples.end()));
    const double maximum = std::max(static_cast<double>(minimum) + 1.0, p95 * 1.35);
    for (const auto sample : result.rawSamples) {
        const double normalized = (std::min(static_cast<double>(sample), maximum) -
                                   static_cast<double>(minimum)) /
                                  (maximum - static_cast<double>(minimum));
        const auto bucket = std::min<std::size_t>(
            bucketCount - 1,
            static_cast<std::size_t>(std::max(0.0, normalized) * static_cast<double>(bucketCount)));
        ++buckets[bucket];
    }
    const std::size_t peak = *std::max_element(buckets.begin(), buckets.end());
    const float chartLeft = bounds.left + 8.0f;
    const float chartBottom = bounds.bottom - 8.0f;
    const float chartWidth = bounds.right - bounds.left - 16.0f;
    const float chartHeight = bounds.bottom - bounds.top - 16.0f;
    const float barWidth = chartWidth / static_cast<float>(bucketCount);
    brush_->SetColor(kAccent);
    for (std::size_t index = 0; index < bucketCount; ++index) {
        const float height = peak == 0 ? 0.0f
            : chartHeight * static_cast<float>(buckets[index]) / static_cast<float>(peak);
        renderTarget_->FillRectangle(
            D2D1::RectF(chartLeft + static_cast<float>(index) * barWidth,
                        chartBottom - height,
                        chartLeft + static_cast<float>(index + 1) * barWidth - 1.0f,
                        chartBottom),
            brush_.Get());
    }
}

void MainWindow::DrawDetails(const DetectionSnapshot& snapshot, const D2D1_RECT_F& bounds) {
    FillRounded(bounds, 12.0f, kPanel);
    if (snapshot.results.empty() || selectedIndex_ >= snapshot.results.size()) {
        DrawTextBlock(L"No result selected", bounds, headingFormat_.Get(), kMuted);
        return;
    }
    const auto& result = snapshot.results[selectedIndex_];
    renderTarget_->PushAxisAlignedClip(bounds, D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
    const float left = bounds.left + 20.0f;
    const float right = bounds.right - 20.0f;
    const float contentWidth = right - left;
    float y = bounds.top + 18.0f - detailScroll_;
    const auto verdictColor = VerdictColor(result.verdict);

    const float titleHeight = MeasureTextHeight(
        result.metadata.title, std::max(40.0f, contentWidth - 125.0f), headingFormat_.Get(), 28.0f);
    DrawTextBlock(result.metadata.title, D2D1::RectF(left, y, right - 120.0f, y + titleHeight),
                  headingFormat_.Get(), kText);
    FillRounded(D2D1::RectF(right - 112.0f, y, right, y + 27.0f), 13.0f,
                D2D1::ColorF(verdictColor.r, verdictColor.g, verdictColor.b, 0.17f));
    DrawTextBlock(VerdictLabel(result.verdict), D2D1::RectF(right - 101.0f, y + 6.0f, right, y + 25.0f),
                  statusFormat_.Get(), verdictColor);
    y += titleHeight + 6.0f;
    const std::wstring capture = result.capturedAtUtc.empty()
        ? L""
        : L"  •  captured " + result.capturedAtUtc;
    DrawTextBlock(result.metadata.category + L"  •  " + SourceLabel(result.metadata.source) + capture,
                  D2D1::RectF(left, y, right, y + 20.0f), smallFormat_.Get(), kMuted);
    y += 25.0f;
    const float descriptionHeight = MeasureTextHeight(
        result.metadata.description, contentWidth, bodyFormat_.Get(), 20.0f);
    DrawTextBlock(result.metadata.description,
                  D2D1::RectF(left, y, right, y + descriptionHeight), bodyFormat_.Get(), kMuted);
    y += descriptionHeight + 12.0f;

    const float summaryHeight = MeasureTextHeight(
        result.summary, contentWidth - 26.0f, bodyFormat_.Get(), 20.0f);
    const float explanationHeight = MeasureTextHeight(
        result.explanation, contentWidth - 26.0f, smallFormat_.Get(), 18.0f);
    const float assessmentHeight = 13.0f + summaryHeight + 8.0f + explanationHeight + 13.0f;
    FillRounded(D2D1::RectF(left, y, right, y + assessmentHeight), 9.0f, kPanelRaised);
    DrawTextBlock(result.summary,
                  D2D1::RectF(left + 13.0f, y + 10.0f,
                              right - 13.0f, y + 10.0f + summaryHeight),
                  bodyFormat_.Get(), verdictColor);
    DrawTextBlock(result.explanation,
                  D2D1::RectF(left + 13.0f, y + 16.0f + summaryHeight,
                              right - 13.0f, y + 16.0f + summaryHeight + explanationHeight),
                  smallFormat_.Get(), kMuted);
    y += assessmentHeight + 14.0f;

    DrawTextBlock(L"Result details", D2D1::RectF(left, y, right, y + 25.0f),
                  headingFormat_.Get(), kText);
    y += 31.0f;
    std::size_t totalRawSamples = result.rawSamples.size();
    for (const auto& series : result.additionalTimingSeries) {
        totalRawSamples += series.rawSamples.size();
    }
    struct DetailMetric { const wchar_t* label; std::wstring value; };
    const std::wstring testId = Utf8ToWide(result.metadata.id);
    const float testIdValueHeight = MeasureTextHeight(
        testId, contentWidth - 18.0f, bodyFormat_.Get(), 18.0f);
    const float testIdCardHeight = 31.0f + testIdValueHeight + 8.0f;
    const D2D1_RECT_F testIdCard = D2D1::RectF(
        left, y, right, y + testIdCardHeight);
    FillRounded(testIdCard, 7.0f, D2D1::ColorF(0x101925));
    DrawTextBlock(L"TEST ID",
                  D2D1::RectF(testIdCard.left + 9.0f, testIdCard.top + 6.0f,
                              testIdCard.right - 7.0f, testIdCard.top + 20.0f),
                  smallFormat_.Get(), kMuted);
    DrawTextBlock(testId,
                  D2D1::RectF(testIdCard.left + 9.0f, testIdCard.top + 24.0f,
                              testIdCard.right - 7.0f, testIdCard.bottom - 5.0f),
                  bodyFormat_.Get(), kText);
    y += testIdCardHeight + 6.0f;

    const std::array<DetailMetric, 6> detailMetrics{{
        {L"EVIDENCE WEIGHT", std::to_wstring(result.confidenceContribution) + L" pts"},
        {L"RELIABILITY", FormatFixed(result.reliability * 100.0, 0) + L"%"},
        {L"ANOMALY SCORE", result.anomalyScore.has_value() && std::isfinite(*result.anomalyScore)
            ? FormatFixed(std::clamp(*result.anomalyScore, 0.0, 100.0), 1) + L" / 100"
            : L"N/A"},
        {L"DURATION", CompactDuration(result)},
        {L"MEASUREMENTS", std::to_wstring(result.measurements.size())},
        {L"RAW VALUES", std::to_wstring(totalRawSamples)}
    }};
    const float detailGap = 6.0f;
    const float detailWidth = (contentWidth - detailGap * 2.0f) / 3.0f;
    for (std::size_t index = 0; index < detailMetrics.size(); ++index) {
        const float column = static_cast<float>(index % 3);
        const float row = static_cast<float>(index / 3);
        const D2D1_RECT_F card = D2D1::RectF(
            left + column * (detailWidth + detailGap), y + row * 58.0f,
            left + column * (detailWidth + detailGap) + detailWidth, y + row * 58.0f + 52.0f);
        FillRounded(card, 7.0f, D2D1::ColorF(0x101925));
        DrawTextBlock(detailMetrics[index].label,
                      D2D1::RectF(card.left + 9.0f, card.top + 6.0f,
                                  card.right - 7.0f, card.top + 20.0f),
                      smallFormat_.Get(), kMuted);
        DrawTextBlock(detailMetrics[index].value,
                      D2D1::RectF(card.left + 9.0f, card.top + 24.0f,
                                  card.right - 7.0f, card.bottom - 4.0f),
                      bodyFormat_.Get(), kText);
    }
    const std::size_t detailRows = (detailMetrics.size() + 2u) / 3u;
    y += static_cast<float>(detailRows) * 58.0f + 4.0f;

    const std::wstring overallContext =
        L"Overall " + std::wstring(VerdictLabel(snapshot.overallVerdict)) + L" • " +
        std::to_wstring(snapshot.confidenceScore) + L"% evidence confidence • " +
        snapshot.confidenceExplanation +
        (snapshot.mixedCaptureTimes ? L" • mixed-age snapshot" : L" • single full-run snapshot");
    const float overallHeight = MeasureTextHeight(
        overallContext, contentWidth - 20.0f, smallFormat_.Get(), 20.0f) + 16.0f;
    FillRounded(D2D1::RectF(left, y, right, y + overallHeight), 7.0f, D2D1::ColorF(0x101925));
    DrawTextBlock(overallContext,
                  D2D1::RectF(left + 10.0f, y + 8.0f, right - 10.0f, y + overallHeight - 6.0f),
                  smallFormat_.Get(), kMuted);
    y += overallHeight + 16.0f;

    if (result.timing.has_value()) {
        DrawTextBlock(L"Timing statistics", D2D1::RectF(left, y, right, y + 25.0f), headingFormat_.Get(), kText);
        y += 32.0f;
        const auto& timing = *result.timing;
        struct Metric { const wchar_t* label; std::wstring value; };
        const double outlierRate = timing.sampleCount == 0
            ? 0.0
            : static_cast<double>(timing.outlierCount) * 100.0 /
              static_cast<double>(timing.sampleCount);
        const std::array<Metric, 10> metrics{{
            {L"SAMPLES", std::to_wstring(timing.sampleCount)},
            {L"MEDIAN", FormatCycles(timing.median)},
            {L"AVERAGE", FormatCycles(timing.average)},
            {L"P95", FormatCycles(timing.p95)},
            {L"MAX", FormatCycles(static_cast<double>(timing.maximum))},
            {L"STD DEV", FormatFixed(timing.standardDeviation, 1)},
            {L"VARIANCE", FormatFixed(timing.variance, 1)},
            {L"Q1", FormatCycles(timing.q1)},
            {L"Q3", FormatCycles(timing.q3)},
            {L"OUTLIERS", std::to_wstring(timing.outlierCount) + L" (" +
                FormatFixed(outlierRate, 1) + L"%)"}
        }};
        const float width = (right - left - 10.0f) / 3.0f;
        for (std::size_t index = 0; index < metrics.size(); ++index) {
            const float column = static_cast<float>(index % 3);
            const float row = static_cast<float>(index / 3);
            const D2D1_RECT_F card = D2D1::RectF(
                left + column * (width + 5.0f), y + row * 62.0f,
                left + column * (width + 5.0f) + width, y + row * 62.0f + 56.0f);
            FillRounded(card, 7.0f, kPanelRaised);
            DrawTextBlock(metrics[index].label, D2D1::RectF(card.left + 9.0f, card.top + 7.0f,
                                                            card.right - 6.0f, card.top + 22.0f),
                          smallFormat_.Get(), kMuted);
            DrawTextBlock(metrics[index].value, D2D1::RectF(card.left + 9.0f, card.top + 26.0f,
                                                            card.right - 6.0f, card.bottom - 4.0f),
                          bodyFormat_.Get(), kText);
        }
        const std::size_t metricRows = (metrics.size() + 2u) / 3u;
        y += static_cast<float>(metricRows) * 62.0f + 5.0f;
        DrawHistogram(result, D2D1::RectF(left, y, right, y + 112.0f));
        y += 116.0f;
        if (!result.rawSamples.empty()) {
            const auto minimum = *std::min_element(result.rawSamples.begin(), result.rawSamples.end());
            const std::wstring axis = L"min " + FormatCycles(static_cast<double>(minimum)) +
                L"    median " + FormatCycles(timing.median) +
                L"    P95 " + FormatCycles(timing.p95) +
                L"    max " + FormatCycles(static_cast<double>(timing.maximum));
            DrawTextBlock(axis, D2D1::RectF(left, y, right, y + 19.0f), smallFormat_.Get(), kMuted);
            y += 25.0f;
        }

        if (!result.additionalTimingSeries.empty()) {
            DrawTextBlock(L"Comparison distributions", D2D1::RectF(left, y, right, y + 25.0f),
                          headingFormat_.Get(), kText);
            y += 31.0f;
            for (const auto& series : result.additionalTimingSeries) {
                const std::wstring summary = TimingMetricSummary(series.statistics);
                const float seriesSummaryHeight = MeasureTextHeight(
                    summary, contentWidth - 20.0f, smallFormat_.Get(), 33.0f);
                const float cardHeight = 33.0f + seriesSummaryHeight + 10.0f;
                const D2D1_RECT_F card = D2D1::RectF(left, y, right, y + cardHeight);
                FillRounded(card, 7.0f, kPanelRaised);
                DrawTextBlock(series.name,
                              D2D1::RectF(card.left + 10.0f, card.top + 7.0f,
                                          card.right - 10.0f, card.top + 25.0f),
                              bodyFormat_.Get(), kText);
                DrawTextBlock(summary,
                              D2D1::RectF(card.left + 10.0f, card.top + 31.0f,
                                          card.right - 10.0f, card.bottom - 7.0f),
                              smallFormat_.Get(), kMuted);
                y += cardHeight + 7.0f;
            }
            y += 7.0f;
        }
    }

    const bool kernelUnavailable = result.verdict == Verdict::Unavailable &&
        result.metadata.source != ObservationSource::UserMode;
    DrawTextBlock(kernelUnavailable ? L"Kernel connection diagnostics" : L"Raw measurements",
                  D2D1::RectF(left, y, right, y + 27.0f), headingFormat_.Get(), kText);
    y += 32.0f;
    if (result.measurements.empty()) {
        const std::wstring emptyText = result.verdict == Verdict::Unavailable
            ? L"No raw fields were collected because this probe was unavailable. The reason and scoring treatment are shown above."
            : L"This test did not emit additional raw fields.";
        const float emptyHeight = MeasureTextHeight(
            emptyText, contentWidth - 20.0f, smallFormat_.Get(), 22.0f) + 16.0f;
        FillRounded(D2D1::RectF(left, y, right, y + emptyHeight), 6.0f, D2D1::ColorF(0x101925));
        DrawTextBlock(emptyText, D2D1::RectF(left + 10.0f, y + 8.0f,
                                              right - 10.0f, y + emptyHeight - 6.0f),
                      smallFormat_.Get(), kMuted);
        y += emptyHeight + 6.0f;
    }
    for (const auto& measurement : result.measurements) {
        const float nameHeight = MeasureTextHeight(
            measurement.name, contentWidth - 18.0f, smallFormat_.Get(), 15.0f);
        const float valueHeight = MeasureTextHeight(
            measurement.value, contentWidth - 18.0f, bodyFormat_.Get(), 18.0f);
        const float interpretationHeight = MeasureTextHeight(
            measurement.interpretation, contentWidth - 18.0f, smallFormat_.Get(), 15.0f);
        const float rowHeight = 10.0f + nameHeight + 5.0f + valueHeight + 5.0f +
                                interpretationHeight + 10.0f;
        const D2D1_RECT_F row = D2D1::RectF(left, y, right, y + rowHeight);
        FillRounded(row, 6.0f, D2D1::ColorF(0x101925));
        float rowY = y + 8.0f;
        DrawTextBlock(measurement.name,
                      D2D1::RectF(left + 9.0f, rowY, right - 9.0f, rowY + nameHeight),
                      smallFormat_.Get(), kMuted);
        rowY += nameHeight + 4.0f;
        DrawTextBlock(measurement.value,
                      D2D1::RectF(left + 9.0f, rowY, right - 9.0f, rowY + valueHeight),
                      bodyFormat_.Get(), kText);
        rowY += valueHeight + 4.0f;
        DrawTextBlock(measurement.interpretation,
                      D2D1::RectF(left + 9.0f, rowY,
                                  right - 9.0f, rowY + interpretationHeight),
                      smallFormat_.Get(), kMuted);
        y += rowHeight + 6.0f;
    }

    if (!result.rawSamples.empty()) {
        y += 10.0f;
        DrawTextBlock(L"Raw sample data", D2D1::RectF(left, y, right, y + 27.0f),
                      headingFormat_.Get(), kText);
        y += 32.0f;
        const std::wstring preview = RawSamplePreview(L"Primary distribution", result.rawSamples, 72);
        const float previewHeight = MeasureTextHeight(
            preview, contentWidth - 20.0f, smallFormat_.Get(), 48.0f) + 18.0f;
        FillRounded(D2D1::RectF(left, y, right, y + previewHeight), 6.0f, D2D1::ColorF(0x0e1621));
        DrawTextBlock(preview, D2D1::RectF(left + 10.0f, y + 8.0f,
                                           right - 10.0f, y + previewHeight - 7.0f),
                      smallFormat_.Get(), kMuted);
        y += previewHeight + 7.0f;
    }
    const std::size_t comparisonPreviewLimit =
        result.additionalTimingSeries.size() > 4u ? 24u : 48u;
    for (const auto& series : result.additionalTimingSeries) {
        if (series.rawSamples.empty()) continue;
        const std::wstring preview = RawSamplePreview(
            series.name, series.rawSamples, comparisonPreviewLimit);
        const float previewHeight = MeasureTextHeight(
            preview, contentWidth - 20.0f, smallFormat_.Get(), 48.0f) + 18.0f;
        FillRounded(D2D1::RectF(left, y, right, y + previewHeight), 6.0f, D2D1::ColorF(0x0e1621));
        DrawTextBlock(preview, D2D1::RectF(left + 10.0f, y + 8.0f,
                                           right - 10.0f, y + previewHeight - 7.0f),
                      smallFormat_.Get(), kMuted);
        y += previewHeight + 7.0f;
    }
    renderTarget_->PopAxisAlignedClip();

    detailContentHeight_ = y + detailScroll_ - bounds.top + 18.0f;
    const float viewport = bounds.bottom - bounds.top;
    if (detailContentHeight_ > viewport) {
        const float trackTop = bounds.top + 10.0f;
        const float trackHeight = viewport - 20.0f;
        const float thumbHeight = std::max(32.0f, trackHeight * viewport / detailContentHeight_);
        const float maximum = detailContentHeight_ - viewport;
        const float thumbTop = trackTop + (trackHeight - thumbHeight) *
            (maximum > 0.0f ? detailScroll_ / maximum : 0.0f);
        FillRounded(D2D1::RectF(bounds.right - 5.0f, trackTop, bounds.right - 2.0f,
                                trackTop + trackHeight), 1.5f, kBorder);
        FillRounded(D2D1::RectF(bounds.right - 6.0f, thumbTop, bounds.right - 1.0f,
                                thumbTop + thumbHeight), 2.5f, kAccent);
    }
}

void MainWindow::StartRunAll() {
    if (running_.exchange(true)) return;
    if (worker_.joinable()) worker_.join();
    progressCompleted_.store(0);
    progressTotal_.store(engine_.Metadata().size());
    activityText_ = L"Preparing AMD probes…";
    detailScroll_ = 0.0f;
    {
        std::lock_guard lock(snapshotMutex_);
        for (auto& result : snapshot_.results) {
            result.verdict = Verdict::Running;
            result.summary = L"Sampling…";
            result.explanation.clear();
            result.measurements.clear();
            result.timing.reset();
            result.rawSamples.clear();
            result.additionalTimingSeries.clear();
            result.confidenceContribution = 0;
            result.anomalyScore.reset();
            result.reliability = 1.0;
            result.duration = std::chrono::milliseconds{};
            result.capturedAtUtc.clear();
        }
        snapshot_.overallVerdict = Verdict::Running;
        snapshot_.confidenceScore = 0;
        snapshot_.confidenceExplanation = L"Sampling is in progress.";
        snapshot_.reportPath.clear();
        snapshot_.reportError.clear();
        snapshot_.mixedCaptureTimes = false;
    }
    UpdateControlState();
    InvalidateRect(window_, nullptr, FALSE);

    worker_ = std::thread([this] {
        DetectionSnapshot next = engine_.RunAll([this](const std::size_t completed, const std::size_t total) {
            if (!closing_.load()) {
                PostMessageW(window_, kMessageProgress,
                             static_cast<WPARAM>(completed), static_cast<LPARAM>(total));
            }
        });
        const auto report = WriteAutomaticReport(next);
        if (report.success) next.reportPath = report.path;
        else next.reportError = report.error;
        {
            std::lock_guard lock(snapshotMutex_);
            snapshot_ = std::move(next);
        }
        running_.store(false);
        if (!closing_.load()) PostMessageW(window_, kMessageResultsReady, 0, 0);
    });
}

void MainWindow::StartRunSelected() {
    StartRunOne(selectedIndex_);
}

void MainWindow::StartRunOne(const std::size_t index) {
    if (running_.exchange(true)) return;
    if (worker_.joinable()) worker_.join();
    detailScroll_ = 0.0f;
    std::string id;
    {
        std::lock_guard lock(snapshotMutex_);
        if (index >= snapshot_.results.size()) {
            running_.store(false);
            return;
        }
        selectedIndex_ = index;
        id = snapshot_.results[index].metadata.id;
        snapshot_.results[index].verdict = Verdict::Running;
        snapshot_.results[index].summary = L"Sampling…";
        snapshot_.results[index].explanation.clear();
        snapshot_.results[index].measurements.clear();
        snapshot_.results[index].timing.reset();
        snapshot_.results[index].rawSamples.clear();
        snapshot_.results[index].additionalTimingSeries.clear();
        snapshot_.results[index].confidenceContribution = 0;
        snapshot_.results[index].anomalyScore.reset();
        snapshot_.results[index].reliability = 1.0;
        snapshot_.results[index].duration = std::chrono::milliseconds{};
        snapshot_.results[index].capturedAtUtc.clear();
    }
    activityText_ = L"Rerunning selected test…";
    progressCompleted_.store(0);
    progressTotal_.store(1);
    UpdateControlState();
    InvalidateRect(window_, nullptr, FALSE);

    worker_ = std::thread([this, index, id = std::move(id)] {
        TestResult result = engine_.RunOne(id);
        DetectionSnapshot next;
        {
            std::lock_guard lock(snapshotMutex_);
            next = snapshot_;
        }
        if (index < next.results.size()) next.results[index] = std::move(result);
        next.timestampUtc = UtcTimestamp();
        next.mixedCaptureTimes = true;
        DetectionEngine::RecalculateOverall(next);
        next.reportPath.clear();
        next.reportError.clear();
        const auto report = WriteAutomaticReport(next);
        if (report.success) next.reportPath = report.path;
        else next.reportError = report.error;
        {
            std::lock_guard lock(snapshotMutex_);
            snapshot_ = std::move(next);
        }
        progressCompleted_.store(1);
        running_.store(false);
        if (!closing_.load()) PostMessageW(window_, kMessageResultsReady, 0, 0);
    });
}

void MainWindow::SaveReportAs() {
    const DetectionSnapshot snapshot = SnapshotCopy();
    if (snapshot.results.empty()) return;

    std::vector<wchar_t> path(32768, L'\0');
    const std::wstring suggested = L"amd-hv-report-" + FileSafeUtcTimestamp() + L".json";
    std::copy(suggested.begin(), suggested.end(), path.begin());
    constexpr wchar_t filter[] = L"JSON report (*.json)\0*.json\0All files (*.*)\0*.*\0\0";
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = window_;
    dialog.lpstrFilter = filter;
    dialog.lpstrFile = path.data();
    dialog.nMaxFile = static_cast<DWORD>(path.size());
    dialog.lpstrDefExt = L"json";
    dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_EXPLORER;
    if (GetSaveFileNameW(&dialog) == FALSE) return;

    const auto result = WriteJsonReport(snapshot, path.data());
    if (!result.success) {
        MessageBoxW(window_, result.error.c_str(), L"Could not save report", MB_OK | MB_ICONERROR);
        return;
    }
    {
        std::lock_guard lock(snapshotMutex_);
        snapshot_.reportPath = result.path;
        snapshot_.reportError.clear();
    }
    activityText_ = L"Report: " + result.path;
    InvalidateRect(window_, nullptr, FALSE);
}

void MainWindow::SelectAt(const float x, const float y) {
    if (!PointInRect(listBounds_, x, y)) return;
    const float relative = y - (listBounds_.top + 10.0f) + listScroll_;
    if (relative < 0.0f) return;
    const auto index = static_cast<std::size_t>(relative / kCardStride);
    const float within = relative - static_cast<float>(index) * kCardStride;
    const auto snapshot = SnapshotCopy();
    if (index >= snapshot.results.size() || within > kCardHeight) return;

    selectedIndex_ = index;
    detailScroll_ = 0.0f;
    const float cardRight = listBounds_.right - 10.0f;
    if (x >= cardRight - 48.0f && x <= cardRight - 10.0f && within >= 10.0f && within <= 34.0f) {
        StartRunOne(index);
    }
    InvalidateRect(window_, nullptr, FALSE);
}

void MainWindow::HandleMouseWheel(const short delta, const float x) {
    const float movement = -static_cast<float>(delta) / static_cast<float>(WHEEL_DELTA) * 72.0f;
    const auto snapshot = SnapshotCopy();
    if (x <= listBounds_.right) {
        const float content = 20.0f + static_cast<float>(snapshot.results.size()) * kCardStride;
        const float maximum = std::max(0.0f, content - (listBounds_.bottom - listBounds_.top));
        listScroll_ = std::clamp(listScroll_ + movement, 0.0f, maximum);
    } else {
        const std::size_t measurements = selectedIndex_ < snapshot.results.size()
            ? snapshot.results[selectedIndex_].measurements.size()
            : 0;
        const float fallbackContent = 310.0f + static_cast<float>(measurements) * 52.0f;
        const float content = std::max(detailContentHeight_, fallbackContent);
        const float maximum = std::max(0.0f, content - (detailBounds_.bottom - detailBounds_.top));
        detailScroll_ = std::clamp(detailScroll_ + movement, 0.0f, maximum);
    }
    InvalidateRect(window_, nullptr, FALSE);
}

DetectionSnapshot MainWindow::SnapshotCopy() const {
    std::lock_guard lock(snapshotMutex_);
    return snapshot_;
}

float MainWindow::CurrentDpiScale() const noexcept {
    return window_ == nullptr ? 1.0f : static_cast<float>(GetDpiForWindow(window_)) / 96.0f;
}

int MainWindow::DipToPixel(const float value) const noexcept {
    return static_cast<int>(std::lround(value * CurrentDpiScale()));
}

} // namespace ahd
