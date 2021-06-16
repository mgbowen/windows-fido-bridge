#pragma once

#include <windows_fido_bridge/types.hpp>

#include <cstdint>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <tuple>
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

void dump_binary(std::stringstream& ss, const uint8_t* buffer, size_t length, size_t indent = 0);

inline void dump_binary(std::stringstream& ss, const byte_vector& binary, size_t indent = 0) {
    dump_binary(ss, reinterpret_cast<const uint8_t*>(binary.data()), binary.size(), indent);
}

inline void dump_binary(std::stringstream& ss, const std::string& binary, size_t indent = 0) {
    dump_binary(ss, reinterpret_cast<const uint8_t*>(binary.data()), binary.size(), indent);
}

inline void dump_binary(std::stringstream& ss, const byte_string& binary, size_t indent = 0) {
    dump_binary(ss, reinterpret_cast<const uint8_t*>(binary.data()), binary.size(), indent);
}

using calloc_ptr = void* (*)(size_t, size_t);

std::tuple<uint8_t*, size_t> calloc_from_data(const uint8_t* buffer, size_t size);
std::tuple<uint8_t*, size_t> calloc_from_data(const char* buffer, size_t size);
std::tuple<uint8_t*, size_t> calloc_from_data(const byte_vector& buffer);
std::tuple<uint8_t*, size_t> calloc_from_data(const std::string& buffer);

template <size_t N>
std::tuple<uint8_t*, size_t> calloc_from_data(const byte_array<N>& buffer) {
    return calloc_from_data(buffer.data(), buffer.size());
}

std::optional<std::string> get_environment_variable(const std::string& variable_name);
std::optional<std::string> get_environment_variable(const char* variable_name);

void set_up_logger(std::string_view log_name);

void log_multiline(const std::string& data, const std::string& indent_str = "");
void log_multiline(std::stringstream& data, const std::string& indent_str = "");
void log_multiline_binary(std::span<const uint8_t> buffer, const std::string& indent_str = "");
void log_multiline_binary(const byte_string& buffer, const std::string& indent_str = "");
void log_multiline_binary(const uint8_t* buffer, size_t length, const std::string& indent_str = "");

std::string_view possibly_null_c_str_to_string_view(const char* c_str);

}  // namespace wfb
