#pragma once

#include <optional>

// https://stackoverflow.com/a/2575145
#ifndef _WINDEF_
class HINSTANCE__;
using HINSTANCE = HINSTANCE__*;
class HWND__;
using HWND = HWND__*;
using HANDLE = void*;
using ATOM = uint16_t;
#endif

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
