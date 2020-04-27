#pragma once

#include <windows_fido_bridge/types.hpp>

#include <cstdint>
#include <string>

namespace wfb {

#define COPYABLE(class_name) \
    class_name(const class_name&) = default; \
    class_name& operator=(const class_name&) = default

#define NON_COPYABLE(class_name) \
    class_name(const class_name&) = delete; \
    class_name& operator=(const class_name&) = delete

#define MOVABLE(class_name) \
    class_name(class_name&&) = default; \
    class_name& operator=(class_name&&) = default

#define NON_MOVABLE(class_name) \
    class_name(class_name&&) = delete; \
    class_name& operator=(class_name&&) = delete

void dump_binary(const uint8_t* buffer, size_t length, size_t indent = 0);

inline void dump_binary(const byte_array& binary, size_t indent = 0) {
    dump_binary(reinterpret_cast<const uint8_t*>(binary.data()), binary.size(), indent);
}

inline void dump_binary(const std::string& binary, size_t indent = 0) {
    dump_binary(reinterpret_cast<const uint8_t*>(binary.data()), binary.size(), indent);
}

}  // namespace wfb
