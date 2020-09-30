#pragma once

#include <windows_fido_bridge/util.hpp>

#include <stdexcept>
#include <string>
#include <string_view>

namespace wfb {

#define CUSTOM_EXCEPTION(name, default_msg) \
    class name : public std::runtime_error { \
    public: \
        name() : std::runtime_error(default_msg) {} \
        name(const std::string& what_arg) : std::runtime_error(what_arg) {} \
        name(const char* what_arg) : std::runtime_error(what_arg) {} \
        \
        COPYABLE(name); \
        MOVABLE(name); \
    }

[[noreturn]] void throw_errno_exception();
[[noreturn]] void throw_errno_exception(const char* error_message);
[[noreturn]] void throw_errno_exception(const std::string& error_message);

}  // namespace wfb
