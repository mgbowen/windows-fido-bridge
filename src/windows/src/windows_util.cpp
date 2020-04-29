#include "windows_util.hpp"

#include "windows_error.hpp"

#include <windows.h>

namespace wfb {

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
        wfb::throw_windows_exception(
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
        wfb::throw_windows_exception("Failed to convert narrow string to wide string");
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
        wfb::throw_windows_exception(
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

}  // namespace wfb
