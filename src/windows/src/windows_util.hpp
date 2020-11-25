#pragma once

#include "windows_fwd.hpp"

#include <memory>
#include <string>
#include <type_traits>

namespace wfb {

struct win32_handle_closer {
    void operator()(HANDLE handle) const;
};

using unique_win32_handle_ptr = std::unique_ptr<std::remove_pointer_t<HANDLE>, win32_handle_closer>;

std::wstring string_to_wide_string(const std::string& str);
std::string wide_string_to_string(const std::wstring& wide_str);

std::wstring get_process_image_path_from_process_id(uint32_t pid);

std::wstring get_file_name_from_file_path(const std::wstring& file_path);

}  // namespace wfb
