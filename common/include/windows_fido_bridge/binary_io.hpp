#pragma once

#include <windows_fido_bridge/format.hpp>
#include <windows_fido_bridge/util.hpp>

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <type_traits>

namespace wfb {

template <typename T, size_t N = sizeof(T), std::enable_if_t<std::is_integral_v<T>, int> = 0>
void integer_to_be_bytes_into(uint8_t* buffer, T value) {
    for (size_t byte_i = 0; byte_i < N; byte_i++) {
        buffer[N - byte_i - 1] = static_cast<uint8_t>(value >> (byte_i * 8));
    }
}

template <typename T, size_t N = sizeof(T), std::enable_if_t<std::is_integral_v<T>, int> = 0>
void integer_to_be_bytes_into(std::vector<uint8_t>& buffer, T value) {
    if (buffer.size() < N) {
        buffer.resize(N);
    }

    integer_to_be_bytes_into<T, N>(buffer.data(), value);
}

template <typename T, size_t ArrayN, size_t IntegerN = sizeof(T),
          std::enable_if_t<std::is_integral_v<T> && ArrayN >= IntegerN, int> = 0>
void integer_to_be_bytes_into(std::array<uint8_t, ArrayN>& buffer, T value) {
    integer_to_be_bytes_into<T, IntegerN>(buffer.data(), value);
}

template <typename T, size_t N = sizeof(T), std::enable_if_t<std::is_integral_v<T>, int> = 0>
std::vector<uint8_t> integer_to_be_bytes(T value) {
    std::vector<uint8_t> buffer;
    integer_to_be_bytes_into<T, N>(buffer, value);
    return buffer;
}

template <typename T, size_t N = sizeof(T), std::enable_if_t<std::is_integral_v<T>, int> = 0>
void be_bytes_to_integer_into(const uint8_t* buffer, T& value) {
    for (size_t byte_i = 0; byte_i < N; byte_i++) {
        value = (value << 8) | buffer[byte_i];
    }
}

template <typename T, size_t N = sizeof(T), std::enable_if_t<std::is_integral_v<T>, int> = 0>
void be_bytes_to_integer_into(const std::vector<uint8_t>& buffer, T& value) {
    if (buffer.size() < N) {
        throw std::runtime_error("buffer is too small to read {} bytes"_format(N));
    }

    be_bytes_to_integer_into(buffer.data(), value);
}

template <typename T, size_t ArrayN, size_t IntegerN = sizeof(T),
          std::enable_if_t<std::is_integral_v<T> && ArrayN >= IntegerN, int> = 0>
void be_bytes_to_integer_into(const std::array<uint8_t, ArrayN>& buffer, T& value) {
    be_bytes_to_integer_into(buffer.data(), value);
}

template <typename T, size_t N = sizeof(T), std::enable_if_t<std::is_integral_v<T>, int> = 0>
T be_bytes_to_integer(const uint8_t* buffer) {
    T value = 0;
    be_bytes_to_integer_into(buffer, value);
    return value;
}

template <typename T, size_t N = sizeof(T), std::enable_if_t<std::is_integral_v<T>, int> = 0>
T be_bytes_to_integer(const std::vector<uint8_t>& buffer) {
    T value = 0;
    be_bytes_to_integer_into(buffer, value);
    return value;
}

template <typename T, size_t ArrayN, size_t IntegerN = sizeof(T), std::enable_if_t<std::is_integral_v<T>, int> = 0>
T be_bytes_to_integer(const std::array<uint8_t, ArrayN>& buffer) {
    T value = 0;
    be_bytes_to_integer_into(buffer, value);
    return value;
}

class binary_reader {
public:
    binary_reader(byte_vector buffer) {
        auto owned_buffer = std::make_unique<const byte_vector>(std::move(buffer));
        _buffer = owned_buffer->data();
        _length = owned_buffer->size();
        _owned_buffer = std::move(owned_buffer);
    }

    template <size_t N>
    binary_reader(const byte_array<N>& buffer)
        : binary_reader(byte_vector(buffer.cbegin(), buffer.cend())) {}

    binary_reader(const std::string& str)
        : binary_reader(byte_vector(str.cbegin(), str.cend())) {}

    binary_reader(std::string_view str)
        : binary_reader(byte_vector(str.cbegin(), str.cend())) {}

    binary_reader(const byte_string& str)
        : binary_reader(byte_vector(str.cbegin(), str.cend())) {}

    binary_reader(const byte_string_view& str)
        : binary_reader(byte_vector(str.cbegin(), str.cend())) {}

    binary_reader(const uint8_t* buffer, size_t length)
        : binary_reader(byte_vector(buffer, buffer + length)) {}

    NON_COPYABLE(binary_reader);
    MOVABLE(binary_reader);

    size_t index() const { return _pos; }
    size_t bytes_remaining() const { return _length - _pos; }

    template <size_t N>
    std::array<uint8_t, N> read_array() {
        std::array<uint8_t, N> buffer;
        read_into(buffer);
        return buffer;
    }

    std::vector<uint8_t> read_vector(size_t num_bytes) {
        std::vector<uint8_t> buffer;
        buffer.resize(num_bytes);
        read_into(buffer.data(), num_bytes);
        return buffer;
    }

    template <size_t N>
    void read_into(std::array<uint8_t, N>& buffer) {
        read_into(buffer.data(), buffer.size());
    }

    void read_into(std::vector<uint8_t>& buffer) {
        read_into(buffer.data(), buffer.size());
    }

    void read_into(uint8_t* dest, size_t num_bytes) {
        _ensure_bytes_available(num_bytes);

        std::memcpy(dest, _buffer + _pos, num_bytes);
        _pos += num_bytes;
    }

    uint8_t read_uint8_t() {
        uint8_t value;
        read_into(&value, 1);
        return value;
    }

    uint8_t peek_uint8_t() const {
        _ensure_bytes_available(1);
        return _buffer[_pos];
    }

    uint16_t read_be_uint16_t() { return _read_be_primitive<uint16_t>(); }
    uint32_t read_be_uint32_t() { return _read_be_primitive<uint32_t>(); }
    uint64_t read_be_uint64_t() { return _read_be_primitive<uint64_t>(); }

private:
    std::unique_ptr<const byte_vector> _owned_buffer;
    const uint8_t* _buffer;
    size_t _length;

    size_t _pos{0};

    void _ensure_bytes_available(size_t num_bytes) const {
        if (num_bytes > bytes_remaining()) {
            throw std::runtime_error("Cannot read {} bytes because only {} bytes are left to read"_format(num_bytes, bytes_remaining()));
        }
    }

    template <typename T>
    T _read_be_primitive() {
        std::array<uint8_t, sizeof(T)> buffer;
        read_into(buffer);
        return be_bytes_to_integer<T>(buffer);
    }
};

class binary_writer {
public:
    size_t bytes_written() const { return _output.size(); }

    void write_uint8_t(uint8_t value) { _output.push_back(value); }
    void write_be_uint16_t(uint16_t value) { _write_integer<2>(value); }
    void write_be_uint32_t(uint32_t value) { _write_integer<4>(value); }
    void write_be_uint64_t(uint64_t value) { _write_integer<8>(value); }

    void write_string(const std::string& buffer) {
        write_bytes(reinterpret_cast<const uint8_t*>(buffer.data()), buffer.size());
    }

    void write_string(const byte_string& buffer) { write_bytes(buffer.data(), buffer.size()); }
    void write_bytes(const byte_vector& buffer) { write_bytes(buffer.data(), buffer.size()); }

    template <size_t N>
    void write_bytes(const byte_array<N>& buffer) { write_bytes(buffer.data(), buffer.size()); }

    void write_bytes(const uint8_t* buffer, size_t length) {
        _output.insert(_output.end(), buffer, buffer + length);
    }

    byte_vector vector() const { return _output; }
    byte_string string() const { return byte_string{_output.cbegin(), _output.cend()}; }

//private:
    byte_vector _output;

    template <size_t N, typename T>
    void _write_integer(T value) {
        for (size_t byte_i = 0; byte_i < N; byte_i++) {
            write_uint8_t(static_cast<uint8_t>(value >> ((N - byte_i - 1) * 8)));
        }
    }
};

}  // namespace wfb
