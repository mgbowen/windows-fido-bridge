#pragma once

#include <windows_fido_bridge/windows_fwd.hpp>

#include <optional>

namespace wfb {

class window {
public:
    window(HINSTANCE h_instance);
    ~window() noexcept;

    HWND hwnd() const;

    void show_window();
    void run_message_loop(std::optional<HANDLE> wait_handle = std::nullopt);

private:
    HINSTANCE _h_instance;
    ATOM _window_class;
    HWND _hwnd;
};

}  // namespace wfb
