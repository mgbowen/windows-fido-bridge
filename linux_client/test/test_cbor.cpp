#include <gtest/gtest.h>

#include "binary_io.hpp"
#include "cbor.hpp"

#include <nlohmann/json.hpp>

#include <initializer_list>
#include <limits>
#include <vector>

using byte_array_t = std::vector<uint8_t>;

template <typename TDestination, typename TBuffer>
TDestination load_cbor_from(TBuffer&& buffer) {
    wfb::binary_reader reader{std::forward<TBuffer>(buffer)};
    return static_cast<TDestination>(wfb::load_cbor(reader));
}

template <typename T>
void test_integer(uint8_t type_byte, T value) {
    std::array<uint8_t, sizeof(T) + 1> bytes{};
    bytes[0] = type_byte;

    wfb::integer_to_be_bytes_into(bytes.data() + 1, value);

    T actual_value = load_cbor_from<T>(bytes);
    ASSERT_EQ(actual_value, value);
}

TEST(CBOR, NonNegativeIntegers) {
    // Examples explicitly mentioned by RFC
    {
        std::vector<uint8_t> bytes = {0b000'01010};
        auto actual_value = load_cbor_from<uint8_t>(bytes);
        ASSERT_EQ(actual_value, 10);
    }

    {
        std::vector<uint8_t> bytes = {0b000'11001, 0x01, 0xf4};
        auto actual_value = load_cbor_from<uint16_t>(bytes);
        ASSERT_EQ(actual_value, 500);
    }

    // Integers up to 16-bit are small enough to just brute-force test every
    // possible value
    for (uint64_t num = 0; num < 24; num++) {
        std::array<uint8_t, 1> bytes{static_cast<uint8_t>(num)};
        auto actual_value = load_cbor_from<uint16_t>(bytes);
        ASSERT_EQ(actual_value, num);
    }

    for (uint64_t num = 0; num < 256; num++) {
        test_integer(24, static_cast<uint8_t>(num));
    }

    for (uint64_t num = 0; num < 65'536; num++) {
        test_integer(25, static_cast<uint16_t>(num));
    }

    // 32-bit and 64-bit have a much larger set of possible values, so just test
    // a few choice values
    std::vector<uint32_t> integers_32_bit = {
        0, 1, 254, 255, 256, 257, 12345, 123456, 1234567, 12345678,
        123456789, 1234567890, 0xffff'fffe, 0xffff'ffff,
    };

    for (auto num : integers_32_bit) {
        test_integer(26, static_cast<uint32_t>(num));
    }

    std::vector<uint64_t> integers_64_bit = {
        0xffff'fffe, 0xffff'ffff, 0x1'0000'0000, 0x1'0000'0001,
        999999999'1, 999999999'12, 999999999'123, 999999999'1234, 999999999'12345,
        999999999'123456, 999999999'1234567, 999999999'12345678, 999999999'123456789,
        0xffff'ffff'ffff'fffe, 0xffff'ffff'ffff'ffff,
    };

    integers_64_bit.insert(integers_64_bit.end(), integers_32_bit.begin(), integers_32_bit.end());

    for (auto num : integers_64_bit) {
        test_integer(27, static_cast<uint64_t>(num));
    }
}

template <size_t N>
void test_negative_integer(uint8_t type_byte, __int128 value) {
    ASSERT_EQ(type_byte >> 5, 1);
    ASSERT_LT(value, 0);

    std::array<uint8_t, N + 1> bytes{};
    bytes[0] = type_byte;

    uint64_t positive_representation = (value * -1) - 1;

    wfb::integer_to_be_bytes_into<decltype(positive_representation), N>(
        bytes.data() + 1, positive_representation
    );

    auto actual_value = load_cbor_from<int64_t>(bytes);
    ASSERT_EQ(actual_value, value);
}

TEST(CBOR, NegativeIntegers) {
    // Example explicitly mentioned by RFC
    {
        std::vector<uint8_t> bytes = {0b001'11001, 0x01, 0xf3};
        auto actual_value = load_cbor_from<int16_t>(bytes);
        ASSERT_EQ(actual_value, -500);
    }

    // Integers up to 16-bit are small enough to just brute-force test every
    // possible value
    for (int64_t num = -24; num < 0; num++) {
        std::array<uint8_t, 1> bytes{static_cast<uint8_t>(0b00100000 | std::abs(num) - 1)};
        auto actual_value = load_cbor_from<int8_t>(bytes);
        ASSERT_EQ(actual_value, num);
    }

    for (int64_t num = -256; num < 0; num++) {
        test_negative_integer<1>(0b00100000 | 24, num);
    }

    for (int64_t num = -65'536; num < 0; num++) {
        test_negative_integer<2>(0b00100000 | 25, num);
    }

    // 32-bit and 64-bit have a much larger set of possible values, so just test
    // a few choice values
    std::vector<int64_t> integers_32_bit = {
        -1, -2, -3, -253, -254, -255, -256, -257, -258, -65534, -65535, -65536, -65537, -65538,
        -123456, -1234567, -12345678, -123456789, -1234567890,
        -2147483647, -2147483648, -2147483649, -2147483650, -2147483651,
        -4294967294, -4294967295, -4294967296,
    };

    for (auto num : integers_32_bit) {
        test_negative_integer<4>(0b00100000 | 26, num);
    }

    std::vector<__int128> integers_64_bit = {
        -999999999'1, -999999999'12, -999999999'123, -999999999'1234, -999999999'12345,
        -999999999'123456, -999999999'1234567, -999999999'12345678, -999999999'123456789,
        -9223372036854775807, std::numeric_limits<int64_t>::min(),
    };

    integers_64_bit.insert(integers_64_bit.end(), integers_32_bit.begin(), integers_32_bit.end());

    for (auto num : integers_64_bit) {
        test_negative_integer<8>(0b00100000 | 27, num);
    }

    // These should fail
    auto negative_limit = static_cast<__int128>(std::numeric_limits<int64_t>::min());

    std::vector<__int128> bad_integers_64_bit = {
        negative_limit - 1, negative_limit - 2, negative_limit - 3,
        static_cast<__int128>(std::numeric_limits<uint64_t>::max()) * -1,

        // Smallest negative 64-bit integer representable by CBOR (excluding
        // bignums)
        (static_cast<__int128>(std::numeric_limits<uint64_t>::max()) * -1) - 1,
    };

    for (auto num : bad_integers_64_bit) {
        EXPECT_THROW(test_negative_integer<8>(0b00100000 | 27, num), std::out_of_range);
    }
}

TEST(CBOR, ByteStrings) {
    // Examples explicitly mentioned by RFC
    {
        std::vector<uint8_t> bytes = {0b010'00101, 'a', 'b', 'c', 'd', 'e'};
        std::vector<uint8_t> expected_bytes = {'a', 'b', 'c', 'd', 'e'};
        std::vector<uint8_t> actual_bytes = load_cbor_from<wfb::cbor_byte_string>(bytes);
        ASSERT_EQ(actual_bytes, expected_bytes);
    }

    {
        std::vector<uint8_t> bytes;
        bytes.resize(503);
        bytes[0] = 0b010'11001;
        bytes[1] = 0x01;
        bytes[2] = 0xf4;

        std::vector<uint8_t> expected_byte_string;
        expected_byte_string.resize(500);

        for (size_t i = 0; i < 500; i++) {
            bytes[i + 3] = expected_byte_string[i] = i % 256;
        }

        std::vector<uint8_t> actual_byte_string = load_cbor_from<wfb::cbor_byte_string>(bytes);
        ASSERT_EQ(actual_byte_string, expected_byte_string);
    }
}

TEST(CBOR, Arrays) {
    {
        std::vector<uint8_t> bytes = {0b100'01010, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        std::vector<uint8_t> expected_items = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        auto actual_items = static_cast<std::vector<uint8_t>>(load_cbor_from<wfb::cbor_array>(bytes));
        ASSERT_EQ(expected_items, actual_items);
    }
}

TEST(CBOR, Maps) {
    {
        std::vector<uint8_t> bytes = {0b101'00100, 0, 1, 2, 3, 4, 5, 6, 7};
        std::map<uint8_t, uint8_t> expected_items = {{0, 1}, {2, 3}, {4, 5}, {6, 7}};
        auto actual_items = static_cast<std::map<uint8_t, uint8_t>>(load_cbor_from<wfb::cbor_map>(bytes));
        ASSERT_EQ(expected_items, actual_items);
    }

    using namespace wfb;

    cbor_text_string asd{"hello"};
    const std::string& foobar = asd;

    cbor_value value{std::string{"hello world"}};
    auto asdasd = value.get<std::string>();
}
