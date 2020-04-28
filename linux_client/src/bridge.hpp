#pragma once

#include <windows_fido_bridge/types.hpp>

#include <cstdint>
#include <string_view>

namespace wfb {

byte_vector invoke_windows_bridge(std::string_view args);
byte_vector invoke_windows_bridge(const byte_vector& args);
byte_vector invoke_windows_bridge(const char* buffer, size_t length);
byte_vector invoke_windows_bridge(const uint8_t* buffer, size_t length);

}  // namespace wfb
