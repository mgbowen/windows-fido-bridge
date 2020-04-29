#include "windows_fido_bridge/exceptions.hpp"

#include <system_error>

namespace wfb {

void throw_errno_exception() {
    throw_errno_exception(static_cast<const char*>(nullptr));
}

void throw_errno_exception(const std::string& error_message) {
    throw_errno_exception(error_message.c_str());
}

void throw_errno_exception(const char* error_message) {
    if (error_message != nullptr) {
        throw std::system_error(errno, std::generic_category(), error_message);
    } else {
        throw std::system_error(errno, std::generic_category());
    }
}

}  // namespace wfb
