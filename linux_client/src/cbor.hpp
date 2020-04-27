#pragma once

#include "binary_io.hpp"
#include "util.hpp"

#include <array>
#include <iostream>
#include <sstream>
#include <unordered_map>
#include <variant>

#include <nlohmann/json.hpp>

namespace wfb {

constexpr const uint8_t CBOR_NON_NEGATIVE_INTEGER = 0;
constexpr const uint8_t CBOR_NEGATIVE_INTEGER = 1;
constexpr const uint8_t CBOR_BYTE_STRING = 2;
constexpr const uint8_t CBOR_TEXT_STRING = 3;
constexpr const uint8_t CBOR_ARRAY = 4;
constexpr const uint8_t CBOR_MAP = 5;

struct cbor_value;

cbor_value load_cbor(binary_reader& reader);
uint64_t read_raw_length(wfb::binary_reader& reader);

struct cbor_integer {
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

    template <typename T, std::enable_if_t<std::is_integral_v<T> && sizeof(T) <= 8, int> = 0>
    cbor_integer(T value) {
        // Signed integer
        if (value >= 0) {
            _type = CBOR_NON_NEGATIVE_INTEGER;
            _raw_value = value;
        } else {
            _type = CBOR_NEGATIVE_INTEGER;
            _raw_value = static_cast<uint64_t>((value + 1) * -1);
        }
    }

    template <typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
    operator T() const {
        switch (_type) {
            case CBOR_NON_NEGATIVE_INTEGER:
                if (_raw_value > std::numeric_limits<T>::max()) {
                    throw std::out_of_range("CBOR non-negative integer cannot fit in specified integer type");
                }

                return _raw_value;
            case CBOR_NEGATIVE_INTEGER:
                if (std::is_unsigned_v<T>) {
                    throw std::out_of_range("Cannot represent CBOR negative integer with unsigned integer type");
                }

                if (_raw_value > std::numeric_limits<T>::max()) {
                    throw std::out_of_range("CBOR negative integer cannot fit in specified integer type");
                }

                return -1 - _raw_value;
            default:
                throw std::runtime_error("Unknown type value for cbor_integer");
        }
    }

    uint64_t raw_value() const { return _raw_value; }

    bool operator==(const cbor_integer& rhs) const {
        return _type == rhs._type && _raw_value == rhs._raw_value;
    }

    bool operator<(const cbor_integer& rhs) const {
        return _type == rhs._type
            ? _raw_value < rhs._raw_value
            : _type < rhs._type;
    }

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

struct cbor_byte_string {
    explicit cbor_byte_string(binary_reader& reader) {
        uint8_t type = reader.peek_uint8_t() >> 5;
        if (type != CBOR_BYTE_STRING) {
            throw std::runtime_error("Invalid type value {:02x} for cbor_byte_string"_format(type));
        }

        uint64_t length = read_raw_length(reader);
        _buffer = reader.read_vector(length);
    }

    template <typename T, enable_if_convertible_without_cvref<T, std::vector<uint8_t>> = 0>
    cbor_byte_string(T&& buffer) : _buffer(std::forward<T>(_buffer)) {}

    const std::vector<uint8_t>& buffer() const { return _buffer; }
    const uint8_t* data() const { return _buffer.data(); }
    size_t size() const { return _buffer.size(); }

    operator std::vector<uint8_t>() const { return _buffer; }

    bool operator==(const cbor_byte_string& rhs) const { return _buffer == rhs._buffer; }
    bool operator<(const cbor_byte_string& rhs) const { return _buffer < rhs._buffer; }

    void dump() const {
        std::stringstream ss;
        dump(ss);
        std::cerr << ss.str() << "\n";
    }

    void dump(std::stringstream& ss) const {
        ss << "b\"";

        for (auto c : _buffer) {
            ss << "{:02x}"_format(c);
        }

        ss << "\"";
    }

private:
    std::vector<uint8_t> _buffer;
};

struct cbor_text_string {
    explicit cbor_text_string(binary_reader& reader) {
        uint8_t type = reader.peek_uint8_t() >> 5;
        if (type != CBOR_TEXT_STRING) {
            throw std::runtime_error("Invalid type value {:02x} for cbor_text_string"_format(type));
        }

        _str.resize(read_raw_length(reader));
        reader.read_into(reinterpret_cast<uint8_t*>(_str.data()), _str.size());
    }

    template <typename T, enable_if_convertible_without_cvref<T, std::string> = 0>
    cbor_text_string(T&& str) : _str(std::forward<T>(str)) {}

    const std::string& string() const { return _str; }
    const char* c_str() const { return _str.data(); }
    const char* data() const { return _str.data(); }
    size_t size() const { return _str.size(); }

    operator std::string() const { return _str; }

    bool operator==(const cbor_text_string& rhs) const { return _str == rhs._str; }
    bool operator<(const cbor_text_string& rhs) const { return _str < rhs._str; }

    void dump() const {
        std::stringstream ss;
        dump(ss);
        std::cerr << ss.str() << "\n";
    }

    void dump(std::stringstream& ss) const {
        ss << "\"";

        for (auto c : _str) {
            if (c == '"') {
                ss << '\\';
            }

            ss << c;
        }

        ss << "\"";
    }

private:
    std::string _str;
};

struct cbor_array {
    explicit cbor_array(binary_reader& reader);

    operator std::vector<cbor_value>() const { return _array; }

    bool operator==(const cbor_array& rhs) const { return _array == rhs._array; }
    bool operator<(const cbor_array& rhs) const { return _array < rhs._array; }

    template <typename T>
    explicit operator std::vector<T>() const {
        return std::vector<T>{_array.begin(), _array.end()};
    }

    void dump() const {
        std::stringstream ss;
        dump(ss);
        std::cerr << ss.str();
    }

    void dump(std::stringstream& ss) const;

private:
    std::vector<cbor_value> _array;
};

struct cbor_map {
    explicit cbor_map(binary_reader& reader);

    operator std::map<cbor_value, cbor_value>() const { return _map; }

    bool operator==(const cbor_map& rhs) const;
    bool operator<(const cbor_map& rhs) const;

    template <typename TKey, typename TValue>
    explicit inline operator std::map<TKey, TValue>() const;

    const std::map<cbor_value, cbor_value>& map() const { return _map; }

    template <typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
    const cbor_value& operator[](T key) const { return _map.at(cbor_value{cbor_integer{key}}); }
    const cbor_value& operator[](std::string key) const;
    //const cbor_value& operator[](const cbor_value& key) { return _map.at(key); }

    void dump() const {
        std::stringstream ss;
        dump(ss);
        std::cerr << ss.str() << "\n";
    }

    void dump(std::stringstream& ss) const;

private:
    std::map<cbor_value, cbor_value> _map;
};

template <typename TDestination, typename TVariant, size_t... TVariantAlternativeTypeIs>
constexpr bool is_convertible_from_variant_alternative_type_helper(
    std::index_sequence<TVariantAlternativeTypeIs...>
) {
    return (std::is_convertible_v<std::variant_alternative_t<TVariantAlternativeTypeIs, TVariant>, TDestination> || ...);
}

template <typename TDestination, typename TVariant, typename Indices = std::make_index_sequence<std::variant_size_v<TVariant>>>
constexpr bool is_convertible_from_variant_alternative_type() {
    return is_convertible_from_variant_alternative_type_helper<TDestination, TVariant>(
        Indices{}
    );
}

static_assert(std::is_convertible_v<cbor_text_string, nlohmann::json>, "ASDASD");

template <typename TDestination, typename TVariant>
struct cbor_value_converter {
    template <typename TSource, enable_if_convertible_without_cvref<TSource, TDestination> = 0>
    TDestination operator()(const TSource& value) const {
        return value;
    }

    template <typename TSource,
        std::enable_if_t<
            is_convertible_from_variant_alternative_type<TDestination, TVariant>() &&
                ! std::is_convertible_v<remove_cvref_t<TSource>, TDestination>,
            int
        > = 0>
    TDestination operator()(const TSource& value) const {
        throw std::runtime_error("Bad type cast");
    }
};

struct cbor_value {
public:
    using storage_type = std::variant<
        cbor_integer,
        cbor_byte_string,
        cbor_text_string,
        cbor_array,
        cbor_map
    >;

    template <typename T, enable_if_convertible_without_cvref<T, storage_type> = 0>
    cbor_value(T&& value) : _storage(std::forward<T>(value)) {}

    cbor_value(const cbor_value& other) : _storage(other._storage) {}
    cbor_value& operator=(const cbor_value& other) {
        _storage = other._storage;
        return *this;
    }

    template <typename T>
    T get() const {
        return std::visit(cbor_value_converter<T, storage_type>{}, _storage);
    }

    void dump() const {
        std::stringstream ss;
        dump(ss);
        std::cerr << ss.str() << "\n";
    }

    void dump(std::stringstream& ss) const {
        std::visit([&](auto&& value) { value.dump(ss); }, _storage);
    }

    template <typename T> explicit operator T() const { return get<T>(); }

    bool operator==(const cbor_value& rhs) const {
        return _storage == rhs._storage;
    }

    bool operator<(const cbor_value& rhs) const {
        return _storage < rhs._storage;
    }

private:
    storage_type _storage;
};

template <typename TKey, typename TValue>
inline cbor_map::operator std::map<TKey, TValue>() const {
    std::map<TKey, TValue> result;
    for (auto&& pair : _map) {
        result.emplace(std::make_pair(pair.first, pair.second));
    }

    return result;
}

//
// Type casting assertions
//

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

}  // namespace wfb
