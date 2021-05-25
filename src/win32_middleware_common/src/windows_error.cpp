#include <windows_fido_bridge/windows_error.hpp>

#include <windows_fido_bridge/format.hpp>

#include <windows.h>

#include <memory>

namespace {

struct windows_error_category : public std::error_category {
    const char* name() const noexcept override { return "windows"; }

    std::string message(int ev) const override {
        // Convert a Windows error code into its associated string using the
        // Windows API. Based on a Microsoft example:
        // https://docs.microsoft.com/en-us/windows/win32/debug/retrieving-the-last-error-code
        LPSTR raw_message_buffer = nullptr;

        // Explicitly use the narrow string variant of FormatMessage because
        // we're returning a narrow string
        DWORD num_chars = FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER
                | FORMAT_MESSAGE_FROM_SYSTEM
                | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,  // Unused
            ev,  // Value from GetLastError()
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),  // Default language
            reinterpret_cast<LPSTR>(&raw_message_buffer),
            0,  // Minimum number of characters to allocate
            nullptr  // Unused
        );

        auto raw_message_buffer_deleter = [](LPSTR ptr) { LocalFree(ptr); };
        std::unique_ptr<char[], decltype(raw_message_buffer_deleter)> message_buffer(
            raw_message_buffer, raw_message_buffer_deleter
        );

        if (num_chars == 0) {
            // Failed to format the message, just return the code itself as a
            // string
            return "Windows error code 0x{:08x}"_format(ev);
        }

        // Strip trailing newlines
        DWORD stripped_num_chars = num_chars;
        for (DWORD i = 0; i < num_chars; i++) {
            char c = message_buffer[num_chars - i - 1];

            if (c == '\n' || c == '\r') {
                stripped_num_chars--;
            } else {
                break;
            }
        }

        return std::string{message_buffer.get(), stripped_num_chars};
    }
};

const windows_error_category category_instance;

}  // namespace

namespace wfb {

std::error_code make_error_code(windows_error_code e) {
    return {static_cast<int>(e.code), category_instance};
}

void throw_windows_exception() {
    throw_windows_exception(static_cast<const char*>(nullptr));
}

void throw_windows_exception(const std::string& error_message) {
    throw_windows_exception(error_message.c_str());
}

void throw_windows_exception(const char* error_message) {
    throw_windows_exception(GetLastError(), error_message);
}

void throw_windows_exception(uint32_t code) {
    throw_windows_exception(code, static_cast<const char*>(nullptr));
}

void throw_windows_exception(uint32_t code, const std::string& error_message) {
    throw_windows_exception(code, error_message.c_str());
}

void throw_windows_exception(uint32_t code, const char* error_message) {
    std::error_code ec = make_error_code(windows_error_code(code));
    if (error_message != nullptr) {
        throw std::system_error(ec, error_message);
    }

    throw std::system_error(ec);
}

}  // namespace wfb
