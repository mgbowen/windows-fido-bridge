#pragma once

#include <string_view>

namespace wfb {

[[noreturn]] void throw_errno_exception();
[[noreturn]] void throw_errno_exception(const char* error_message);
[[noreturn]] void throw_errno_exception(const std::string& error_message);

}  // namespace wfb
