#pragma once

#include <windows_fido_bridge/types.hpp>
#include <windows_fido_bridge/util.hpp>

#include <type_traits>
#include <utility>

namespace wfb {

class binary_reader;
class cbor_value;

namespace detail {

cbor_value parse_cbor_from_reader(binary_reader& reader);

}  // namespace detail

template <typename T, typename... Args>
T parse_cbor(Args&&... args) {
    binary_reader reader(std::forward<Args>(args)...);
    return static_cast<T>(detail::parse_cbor_from_reader(reader));
}

template <typename T, typename BinaryReader>
std::enable_if_t<std::is_same_v<remove_cvref_t<BinaryReader>, binary_reader>, T>
parse_cbor(BinaryReader&& reader) {
    return static_cast<T>(detail::parse_cbor_from_reader(std::forward<BinaryReader>(reader)));
}

}  // namespace wfb
