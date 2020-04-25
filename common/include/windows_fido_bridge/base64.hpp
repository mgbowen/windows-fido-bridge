#pragma once

#include <cstdint>
#include <string>

namespace wfb {

std::string base64_encode(const uint8_t* buffer, size_t length);
std::string base64_decode(const std::string& str);
std::string base64_decode(const uint8_t* buffer, size_t length);

}  // namespace wfb
