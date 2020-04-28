#pragma once

#include <windows_fido_bridge/cbor/detail.hpp>

#include <windows_fido_bridge/binary_io.hpp>
#include <windows_fido_bridge/util.hpp>

#include <array>
#include <iostream>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <variant>

#include <nlohmann/json.hpp>

namespace wfb {

class cbor_value;

class cbor_string {
public:
    explicit cbor_string(binary_reader& reader) {
        _type = reader.peek_uint8_t() >> 5;
        if (_type != CBOR_TEXT_STRING && _type != CBOR_BYTE_STRING) {
            throw std::runtime_error("Invalid type value {:02x} for cbor_string"_format(_type));
        }

        _str.resize(read_raw_length(reader));
        reader.read_into(reinterpret_cast<uint8_t*>(_str.data()), _str.size());
    }

    cbor_string(std::string str) : _str(std::move(str)) {}
    cbor_string(const char* str) : _str(str) {}

    bool is_binary() const { return _type == CBOR_BYTE_STRING; }
    bool is_text() const { return _type == CBOR_TEXT_STRING; }

    const std::string& string() const { return _str; }
    const char* c_str() const { return _str.data(); }
    const char* data() const { return _str.data(); }
    size_t size() const { return _str.size(); }

    operator std::string() const { return _str; }
    operator std::string_view() const { return _str; }

    operator byte_vector() const {
        byte_vector result;
        result.resize(size());
        std::memcpy(result.data(), data(), size());
        return result;
    }

    bool operator==(const cbor_string& rhs) const { return _str == rhs._str; }
    bool operator<(const cbor_string& rhs) const { return _str < rhs._str; }

    void dump() const {
        std::stringstream ss;
        dump(ss);
        std::cerr << ss.str() << "\n";
    }

    void dump(std::stringstream& ss) const {
        ss << "\"";

        if (is_binary()) {
            ss << 'b';
        }

        for (auto c : _str) {
            if (c == '"') {
                ss << '\\';
            }

            ss << c;
        }

        ss << "\"";
    }

private:
    uint8_t _type;
    std::string _str;
};

//
// Type casting assertions
//

/*
static_assert(std::is_convertible_v<cbor_integer, int8_t>, "cbor_integer not convertible to int8_t");
static_assert(std::is_convertible_v<cbor_integer, uint8_t>, "cbor_integer not convertible to uint8_t");
static_assert(std::is_convertible_v<cbor_integer, int16_t>, "cbor_integer not convertible to int16_t");
static_assert(std::is_convertible_v<cbor_integer, uint16_t>, "cbor_integer not convertible to uint16_t");
static_assert(std::is_convertible_v<cbor_integer, int32_t>, "cbor_integer not convertible to int32_t");
static_assert(std::is_convertible_v<cbor_integer, uint32_t>, "cbor_integer not convertible to uint32_t");
static_assert(std::is_convertible_v<cbor_integer, int64_t>, "cbor_integer not convertible to int64_t");
static_assert(std::is_convertible_v<cbor_integer, uint64_t>, "cbor_integer not convertible to uint64_t");

static_assert(std::is_convertible_v<cbor_text_string, std::string>, "cbor_text_string not convertible to std::string");
static_assert(std::is_convertible_v<cbor_byte_string, std::vector<uint8_t>>, "cbor_byte_string not convertible to std::vector<uint8_t>");
*/

}  // namespace wfb
