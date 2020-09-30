#include "window.hpp"

#include "windows_error.hpp"

#include <windows.h>

#include <vector>

namespace {

constexpr const wchar_t* CLASS_NAME = L"windows-fido-bridge";

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

}  // namespace

namespace wfb {

window::window(HINSTANCE h_instance) : _h_instance(h_instance) {
    // Register the window class
    WNDCLASSEX wcex{
        .cbSize = sizeof(WNDCLASSEX),
        .lpfnWndProc = WindowProc,
        .hInstance = _h_instance,
        .hCursor = LoadCursor(NULL, IDC_ARROW),
        .lpszClassName = CLASS_NAME,
    };

    _window_class = RegisterClassEx(&wcex);
    if (_window_class == 0) {
        throw_windows_exception("Call to RegisterClassEx() failed");
    }

    _hwnd = CreateWindowEx(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW,  // Optional window styles.
        CLASS_NAME,  // Window class
        L"windows-fido-bridge",  // Window text
        WS_POPUPWINDOW,  // Window style

        // Size and position
        960, 540, 0, 0,

        NULL,  // Parent window
        NULL,  // Menu
        h_instance,  // Instance handle
        NULL   // Additional application data
    );

    if (_hwnd == nullptr) {
        throw_windows_exception("Call to CreateWindowEx() failed");
    }
}

window::~window() noexcept {
    if (!UnregisterClass(CLASS_NAME, _h_instance)) {
        throw_windows_exception("Call to UnregisterClass() failed");
    }
}

HWND window::hwnd() const { return _hwnd; }

void window::show_window() {
    ShowWindow(_hwnd, SW_SHOWNORMAL);
    SetForegroundWindow(_hwnd);
}

void window::run_message_loop(std::optional<HANDLE> wait_handle) {
    // Based on https://devblogs.microsoft.com/oldnewthing/20050217-00/?p=36423
    while (true) {
        std::vector<HANDLE> wait_handles;
        if (wait_handle) {
            wait_handles.push_back(*wait_handle);
        }

        HANDLE wait_handle_value = *wait_handle;
        DWORD wait_result = MsgWaitForMultipleObjects(
            wait_handles.size(),
            wait_handles.data(),
            false,
            INFINITE,
            QS_ALLINPUT
        );

        switch (wait_result) {
            case WAIT_OBJECT_0: {
                // Handle we're waiting on triggered
                return;
            }
            case WAIT_OBJECT_0 + 1: {
                MSG msg{};
                while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
                    if (msg.message == WM_QUIT) {
                        PostQuitMessage((int)msg.wParam);
                        return;
                    }

                    TranslateMessage(&msg);
                    DispatchMessage(&msg);
                }

                break;
            }
            case WAIT_FAILED: {
                throw_windows_exception("Call to MsgWaitForMultipleObjects() failed");
            }
        }
    }
}

}  // namespace wfb

namespace {

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_DESTROY: {
            PostQuitMessage(0);
            break;
        }
        default: {
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
        }
    }

    return true;
}

}  // namespace
