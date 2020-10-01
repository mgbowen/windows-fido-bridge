#pragma once

namespace wfb {

class binary_reader;
class cbor_value;

template <typename T, typename... Args, typename TCborValue = cbor_value>
T parse_cbor(Args&&... args);

template <typename T, typename TBinaryReader, typename TCborValue = cbor_value>
std::enable_if_t<std::is_same_v<remove_cvref_t<TBinaryReader>, binary_reader>, T>
parse_cbor(TBinaryReader&& reader);

}  // namespace wfb
