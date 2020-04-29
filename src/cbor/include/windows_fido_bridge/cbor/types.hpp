#pragma once

#include <string>
#include <cstdint>

namespace wfb {

namespace literals {

inline const uint8_t* operator "" _bytes(const char* chars, size_t size) {
    return reinterpret_cast<const uint8_t*>(chars);
}

}  // namespace literals

}  // namespace wfb
