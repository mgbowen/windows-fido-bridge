#pragma once

#include "windows_fwd.hpp"

#include <optional>

namespace wfb {

class window {
public:
    window(HINSTANCE h_instance);
    ~window() noexcept;

    HWND hwnd() const;

    void show_window();
    void run_message_loop();
    void wait_handle(HANDLE handle);

private:
    HINSTANCE _h_instance;
    ATOM _window_class;
    HWND _hwnd;

    void _run_message_loop(std::optional<HANDLE> wait_handle);
};

}  // namespace wfb
