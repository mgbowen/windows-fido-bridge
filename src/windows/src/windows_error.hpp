#pragma once

#include <system_error>
#include <string>

namespace wfb {

struct windows_error_code {
    explicit windows_error_code(uint32_t code_) noexcept : code(code_) {}

    uint32_t code;
};

std::error_code make_error_code(windows_error_code e);

void throw_windows_exception();
void throw_windows_exception(const std::string& error_message);
void throw_windows_exception(const char* error_message);
void throw_windows_exception(uint32_t code);
void throw_windows_exception(uint32_t code, const std::string& error_message);
void throw_windows_exception(uint32_t code, const char* error_message);

}  // namespace wfb

// Make the standard library aware of our custom error code
namespace std { template <> struct is_error_code_enum<wfb::windows_error_code> : true_type {}; }
