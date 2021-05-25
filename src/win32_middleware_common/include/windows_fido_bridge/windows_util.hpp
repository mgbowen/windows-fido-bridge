#pragma once

#include <windows_fido_bridge/format.hpp>
#include <windows_fido_bridge/windows_error.hpp>
#include <windows_fido_bridge/windows_fwd.hpp>

#include <memory>
#include <string>
#include <type_traits>

namespace wfb {

struct win32_handle_closer {
    void operator()(HANDLE handle) const;
};

using unique_win32_handle_ptr = std::unique_ptr<std::remove_pointer_t<HANDLE>, win32_handle_closer>;

std::wstring string_to_wide_string(std::string_view str);
std::string wide_string_to_string(std::wstring_view wide_str);

std::wstring get_process_image_path_from_process_id(uint32_t pid);

std::wstring get_file_name_from_file_path(const std::wstring& file_path);

bool is_library_loaded_by_current_process(std::wstring_view library_file_name);

namespace detail {

void* GetProcAddress(HMODULE module, const char* proc_name);

}  // namespace detail

template <typename T>
T get_proc_address(HINSTANCE library, const char* method_name) {
    auto result = reinterpret_cast<T>(detail::GetProcAddress(library, method_name));
    if (result == nullptr) {
        throw_windows_exception("Failed to find method {}"_format(method_name));
    }

    return result;
}

}  // namespace wfb
