#include <windows_fido_bridge/windows_util.hpp>

#include <windows_fido_bridge/format.hpp>
#include <windows_fido_bridge/windows_error.hpp>

#include <spdlog/spdlog.h>

#include <windows.h>
#include <shlwapi.h>

#include <array>

namespace wfb {

namespace {

std::vector<HMODULE> get_current_process_loaded_module_handles();
std::wstring get_current_process_module_file_path(HMODULE module_handle);

}  // namespace

void win32_handle_closer::operator()(HANDLE handle) const {
    if (!CloseHandle(handle)) {
        spdlog::debug("Failed to close handle {}", reinterpret_cast<void*>(handle));
    }
}

std::wstring string_to_wide_string(std::string_view str) {
    // Get the number of bytes required to hold the converted string
    int num_wchars = MultiByteToWideChar(
        CP_UTF8,
        0,  // Unused flags
        str.data(),
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

std::string wide_string_to_string(std::wstring_view wide_str) {
    // Get the number of bytes required to hold the converted string
    int num_chars = WideCharToMultiByte(
        CP_UTF8,
        0,  // Unused flags
        wide_str.data(),
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
    if (file_path.size() >= MAX_PATH) {
        throw std::out_of_range("File path is too large");
    }

    const wchar_t* file_path_ptr = file_path.c_str();
    const wchar_t* file_name_ptr = PathFindFileNameW(file_path_ptr);

    if (file_path_ptr == file_name_ptr) {
        throw std::invalid_argument("Failed to extract a file name from the file path");
    }

    return std::wstring(file_name_ptr);
}

namespace detail {

void* GetProcAddress(HMODULE module, const char* proc_name) {
    return reinterpret_cast<void*>(::GetProcAddress(module, proc_name));
}

}  // namespace detail

}  // namespace wfb
