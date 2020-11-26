#include "window.hpp"

#include "windows_error.hpp"
#include "windows_util.hpp"

#include <windows_fido_bridge/format.hpp>

#include <spdlog/spdlog.h>

#include <windows.h>

#include <vector>

namespace {

constexpr const wchar_t* CLASS_NAME = L"windows-fido-bridge";

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

struct foreground_window_info {
    HWND hwnd;
    std::wstring owner_process_image_file_path;
    std::wstring owner_process_image_file_name;
};

foreground_window_info get_foreground_window_info();

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

    if (!SetForegroundWindow(_hwnd)) {
        // Tried to bring the window to which we attach WebAuthn calls to the
        // foreground, but the request was denied. A denial should be a fairly
        // rare occurrence, but it's known to happen if we're running inside an
        // integrated terminal via VS Code's Remote WSL extension (which, as far
        // as I can tell, runs the entire execution context inside a separate
        // process that isn't part of the parent VS Code's process tree).
        //
        // Not being able to set the foreground window to the one hosting the
        // WebAuthn calls is problematic from a UX and security perspective
        // because it makes it very likely that a user may enter their security
        // key's PIN into a window other than the WebAuthn's window, forcing
        // them to explicitly Alt+Tab or click into the window before typing it.
        spdlog::debug(
            "Tried to set the foreground window to the windows-fido-bridge host window, but the "
            "request was denied."
        );

        bool set_foreground_window_successfully = false;

        try {
            foreground_window_info foreground_info = get_foreground_window_info();
            if (foreground_info.owner_process_image_file_name == L"Code.exe") {
                // One workaround that's known to work with VS Code specifically
                // is to set the window's parent to the foreground window. I'm
                // unclear what problems might arise from doing this, so
                // explicitly log that we're doing it to make issue reporting
                // easier.
                spdlog::debug(
                    "Detected current foreground window is VS Code, attempting to reparent the "
                    "windows-fido-bridge host window to it."
                );

                if (SetParent(_hwnd, foreground_info.hwnd) == nullptr) {
                    throw_windows_exception("Call to SetParent() failed");
                }

                spdlog::debug("Successfully reparented windows-fido-bridge host window.");
                set_foreground_window_successfully = true;
            }
        } catch (const std::exception& ex) {
            spdlog::debug("Failed to reparent windows-fido-bridge host window: {}", ex.what());
        } catch (...) {
            spdlog::debug("Failed to reparent windows-fido-bridge host window (unknown exception)");
        }

        if (!set_foreground_window_successfully) {
            spdlog::warn(
                "Please ensure your foreground window is set to the Windows security key prompt "
                "before entering your security key PIN."
            );
        }
    }
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

foreground_window_info get_foreground_window_info() {
    HWND foreground_window = GetForegroundWindow();
    if (foreground_window == nullptr) {
        wfb::throw_windows_exception("Call to GetForegroundWindow() failed");
    }

    DWORD foreground_pid = 0;
    DWORD foreground_thread_id = GetWindowThreadProcessId(foreground_window, &foreground_pid);
    if (foreground_thread_id == 0) {
        wfb::throw_windows_exception("Call to GetWindowThreadProcessId() failed");
    }

    spdlog::debug("Foreground window thread ID: {}", foreground_thread_id);
    spdlog::debug("Foreground window process ID: {}", foreground_pid);

    std::wstring wide_image_file_path = wfb::get_process_image_path_from_process_id(foreground_pid);

    spdlog::debug(
        "Foreground window process image file path: \"{}\"",
        wfb::wide_string_to_string(wide_image_file_path)
    );

    std::wstring wide_image_file_name = wfb::get_file_name_from_file_path(wide_image_file_path);

    spdlog::debug(
        "Foreground window process image file name: \"{}\"",
        wfb::wide_string_to_string(wide_image_file_name)
    );

    return foreground_window_info {
        .hwnd = foreground_window,
        .owner_process_image_file_path = std::move(wide_image_file_path),
        .owner_process_image_file_name = std::move(wide_image_file_name),
    };
}

}  // namespace
