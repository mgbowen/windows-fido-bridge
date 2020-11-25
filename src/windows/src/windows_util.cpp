#include "windows_util.hpp"

#include "windows_error.hpp"

#include <windows_fido_bridge/format.hpp>

#include <spdlog/spdlog.h>

#include <windows.h>

namespace wfb {

void win32_handle_closer::operator()(HANDLE handle) const {
    if (!CloseHandle(handle)) {
        spdlog::debug("Failed to close handle {}", reinterpret_cast<void*>(handle));
    }
}

std::wstring string_to_wide_string(const std::string& str) {
    // Get the number of bytes required to hold the converted string
    int num_wchars = MultiByteToWideChar(
        CP_UTF8,
        0,  // Unused flags
        str.c_str(),
        str.size(),
        nullptr,
        0  // We want to know the buffer size required to hold the new string
    );

    if (num_wchars == 0) {
        throw_windows_exception(
            "Failed to determine buffer size needed to convert narrow string to wide string"
        );
    }

    // Allocate a buffer of the size required to hold the converted string and
    // do the actual conversion
    std::wstring converted_string;
    converted_string.resize(num_wchars);

    int result = MultiByteToWideChar(
        CP_UTF8,
        0,  // Unused flags
        str.data(),
        str.size(),
        converted_string.data(),
        converted_string.size()
    );

    if (result == 0) {
        throw_windows_exception("Failed to convert narrow string to wide string");
    }

    return converted_string;
}

std::string wide_string_to_string(const std::wstring& wide_str) {
    // Get the number of bytes required to hold the converted string
    int num_chars = WideCharToMultiByte(
        CP_UTF8,
        0,  // Unused flags
        wide_str.c_str(),
        wide_str.size(),
        nullptr,
        0,
        nullptr,  // Use default character to replace unrepresentable characters
        nullptr  // Don't care if unrepresentable characters were replaced
    );

    if (num_chars == 0) {
        throw_windows_exception(
            "Failed to determine buffer size needed to convert wide string to narrow string"
        );
    }

    // Allocate a buffer of the size required to hold the converted string and
    // do the actual conversion
    std::string converted_string;
    converted_string.resize(num_chars);

    int result = WideCharToMultiByte(
        CP_UTF8,
        0,  // Unused flags
        wide_str.data(),
        wide_str.size(),
        converted_string.data(),
        converted_string.size(),
        nullptr,
        nullptr
    );

    return converted_string;
}

std::wstring get_process_image_path_from_process_id(uint32_t pid) {
    HANDLE raw_foreground_process_handle = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        false,  // bInheritHandle
        pid
    );
    if (raw_foreground_process_handle == nullptr) {
        throw_windows_exception("Call to OpenProcess() failed");
    }

    unique_win32_handle_ptr foreground_process_handle(raw_foreground_process_handle);

    DWORD foreground_process_path_size = MAX_PATH;
    wchar_t foreground_process_path_buf[MAX_PATH] = {};
    bool query_succeeded = QueryFullProcessImageName(
        foreground_process_handle.get(),
        0,  // dwFlags
        foreground_process_path_buf,
        &foreground_process_path_size
    );
    if (!query_succeeded) {
        throw_windows_exception("Call to QueryFullProcessImageName() failed");
    }

    return std::wstring{foreground_process_path_buf, foreground_process_path_size};
}

std::wstring get_file_name_from_file_path(const std::wstring& file_path) {
    wchar_t file_name_no_ext_buf[MAX_PATH];
    wchar_t file_ext_buf[MAX_PATH];

    errno_t err = _wsplitpath_s(
        file_path.c_str(),
        nullptr,  // drive
        0,  // driveNumberOfElements
        nullptr,  // dir
        0,  // dirNumberOfElements
        file_name_no_ext_buf,
        sizeof(file_name_no_ext_buf),
        file_ext_buf,
        sizeof(file_ext_buf)
    );
    if (err != 0) {
        throw std::runtime_error(
            "Failed to get file name from file path \"{}\""_format(
                wide_string_to_string(file_path)
            )
        );
    }

    return L"{}{}"_format(file_name_no_ext_buf, file_ext_buf);
}

}  // namespace wfb
