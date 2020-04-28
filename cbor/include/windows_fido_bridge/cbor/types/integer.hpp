#pragma once

#include <windows_fido_bridge/cbor/detail.hpp>

#include <windows_fido_bridge/binary_io.hpp>

#include <cstdint>
#include <iostream>
#include <type_traits>
#include <sstream>

namespace wfb {

namespace detail {

template <typename T>
constexpr bool can_fit_in_cbor_integer_v =
    std::is_integral_v<T> && sizeof(T) <= sizeof(uint64_t);

}  // namespace detail

class cbor_integer {
public:
    explicit cbor_integer(binary_reader& reader) {
        uint8_t initial_byte = reader.read_uint8_t();
        _type = initial_byte >> 5;
        uint8_t additional_info = initial_byte & 0x1f;

        if (additional_info < 24) {
            _raw_value = additional_info;
        } else {
            switch (additional_info) {
                case 24: _raw_value = reader.read_uint8_t(); break;
                case 25: _raw_value = reader.read_be_uint16_t(); break;
                case 26: _raw_value = reader.read_be_uint32_t(); break;
                case 27: _raw_value = reader.read_be_uint64_t(); break;
                default:
                    throw std::runtime_error(
                        "Invalid additional information value {} for length (initial_byte = 0x{:02x})"_format(
                            additional_info, initial_byte
                        )
                    );
            }
        }
    }

    template <typename T, std::enable_if_t<detail::can_fit_in_cbor_integer_v<T>, int> = 0>
    constexpr cbor_integer(T value) {
        if (value >= 0) {
            _type = CBOR_NON_NEGATIVE_INTEGER;
            _raw_value = value;
        } else {
            _type = CBOR_NEGATIVE_INTEGER;
            _raw_value = static_cast<uint64_t>((value + 1) * -1);
        }
    }

    template <typename T, std::enable_if_t<detail::can_fit_in_cbor_integer_v<T>, int> = 0>
    constexpr operator T() const {
        switch (_type) {
            case CBOR_NON_NEGATIVE_INTEGER:
                if (_raw_value > std::numeric_limits<T>::max()) {
                    throw std::overflow_error("CBOR non-negative integer cannot fit in specified integer type");
                }

                return _raw_value;
            case CBOR_NEGATIVE_INTEGER:
                if (std::is_unsigned_v<T>) {
                    throw std::overflow_error("Cannot represent CBOR negative integer with unsigned integer type");
                }

                if (_raw_value > std::numeric_limits<T>::max()) {
                    throw std::overflow_error("CBOR negative integer cannot fit in specified integer type");
                }

                return -1 - _raw_value;
            default:
                throw std::runtime_error("Unknown type value for cbor_integer");
        }
    }

    constexpr uint64_t raw_value() const { return _raw_value; }

    bool operator<(const cbor_integer& rhs) const {
        return _type == rhs._type
            ? _raw_value < rhs._raw_value
            : _type < rhs._type;
    }

    bool operator==(const cbor_integer& rhs) const { return !(*this < rhs) && !(rhs < *this); }
    bool operator!=(const cbor_integer& rhs) const { return !(*this == rhs); }
    bool operator>(const cbor_integer& rhs) const { return !(*this < rhs) && *this != rhs; }
    bool operator>=(const cbor_integer& rhs) const { return !(*this < rhs); }
    bool operator<=(const cbor_integer& rhs) const { return *this < rhs || *this == rhs; }

    void dump() const {
        std::stringstream ss;
        dump(ss);
        std::cerr << ss.str() << "\n";
    }

    void dump(std::stringstream& ss) const {
        if (_type == CBOR_NEGATIVE_INTEGER) {
            // Use special logic to handle this so we don't run into potential
            // overflow issues for very small negative numbers
            ss << '-' << _raw_value + 1;
        } else {
            ss << static_cast<uint64_t>(*this);
        }
    }

private:
    uint8_t _type;
    uint64_t _raw_value;
};

template <typename T, std::enable_if_t<detail::can_fit_in_cbor_integer_v<T>, int> = 0>
bool operator==(T lhs, const cbor_integer& rhs) { return cbor_integer(lhs) == rhs; }

template <typename T, std::enable_if_t<detail::can_fit_in_cbor_integer_v<T>, int> = 0>
bool operator!=(T lhs, const cbor_integer& rhs) { return cbor_integer(lhs) != rhs; }

template <typename T, std::enable_if_t<detail::can_fit_in_cbor_integer_v<T>, int> = 0>
bool operator<(T lhs, const cbor_integer& rhs) { return cbor_integer(lhs) < rhs; }

template <typename T, std::enable_if_t<detail::can_fit_in_cbor_integer_v<T>, int> = 0>
bool operator>(T lhs, const cbor_integer& rhs) { return cbor_integer(lhs) > rhs; }

template <typename T, std::enable_if_t<detail::can_fit_in_cbor_integer_v<T>, int> = 0>
bool operator<=(T lhs, const cbor_integer& rhs) { return cbor_integer(lhs) <= rhs; }

template <typename T, std::enable_if_t<detail::can_fit_in_cbor_integer_v<T>, int> = 0>
bool operator>=(T lhs, const cbor_integer& rhs) { return cbor_integer(lhs) >= rhs; }

}  // namespace wfb
