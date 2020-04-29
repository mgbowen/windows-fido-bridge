#pragma once

#include <windows_fido_bridge/types.hpp>

#include <cstdint>
#include <string>
#include <type_traits>

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

template <typename T>
using remove_cvref_t = std::remove_cv_t<std::remove_reference_t<T>>;

template <typename T, typename U>
constexpr bool is_same_remove_cvref_v = std::is_same_v<remove_cvref_t<T>, remove_cvref_t<U>>;

template <typename T, typename U>
using enable_if_convertible_without_cvref =
    std::enable_if_t<std::is_convertible_v<remove_cvref_t<T>, remove_cvref_t<U>>, int>;

template <typename T, typename U>
using enable_if_not_convertible_without_cvref =
    std::enable_if_t<! std::is_convertible_v<remove_cvref_t<T>, U>, int>;

template <typename T, typename U>
constexpr bool is_explicitly_convertible =
    std::is_constructible_v<remove_cvref_t<T>, remove_cvref_t<U>> &&
        ! std::is_convertible_v<remove_cvref_t<T>, remove_cvref_t<U>>;

void dump_binary(const uint8_t* buffer, size_t length, size_t indent = 0);

inline void dump_binary(const byte_vector& binary, size_t indent = 0) {
    dump_binary(reinterpret_cast<const uint8_t*>(binary.data()), binary.size(), indent);
}

inline void dump_binary(const std::string& binary, size_t indent = 0) {
    dump_binary(reinterpret_cast<const uint8_t*>(binary.data()), binary.size(), indent);
}

}  // namespace wfb
