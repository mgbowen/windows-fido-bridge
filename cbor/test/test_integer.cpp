#include <windows_fido_bridge/binary_io.hpp>
#include <windows_fido_bridge/cbor.hpp>

#include <gtest/gtest.h>

#include <initializer_list>
#include <limits>
#include <vector>

template <typename T> void test_integer_roundtrip(T value);

template <typename T>
void test_integer(uint8_t type_byte, T expected_value) {
    std::array<uint8_t, sizeof(T) + 1> expected_bytes{};
    expected_bytes[0] = type_byte;

    wfb::integer_to_be_bytes_into(expected_bytes.data() + 1, expected_value);

    auto actual_value_cbor = wfb::parse_cbor<wfb::cbor_integer>(expected_bytes);
    T actual_value = actual_value_cbor;
    ASSERT_EQ(actual_value, expected_value);

    test_integer_roundtrip<T>(expected_value);
}

template <typename T>
void test_integer_roundtrip(T value) {
    wfb::cbor_integer initial_cbor{value};

    uint64_t raw_value = initial_cbor.raw_value();
    wfb::byte_vector actual_bytes = wfb::dump_cbor(initial_cbor);
    wfb::binary_reader actual_bytes_reader(actual_bytes.data(), actual_bytes.size());

    uint8_t actual_initial_byte = actual_bytes_reader.read_uint8_t();
    ASSERT_EQ(actual_initial_byte >> 5, value >= 0 ? 0 : 1);
    uint8_t actual_additional_info = actual_initial_byte & 0x1f;

    if (raw_value < 24) {
        ASSERT_EQ(actual_bytes.size(), 1);
        ASSERT_EQ(actual_additional_info, raw_value);
    } else if (raw_value <= std::numeric_limits<uint8_t>::max()) {
        ASSERT_EQ(actual_bytes.size(), 2);
        ASSERT_EQ(actual_bytes_reader.read_uint8_t(), raw_value);
    } else if (raw_value <= std::numeric_limits<uint16_t>::max()) {
        ASSERT_EQ(actual_bytes.size(), 3);
        ASSERT_EQ(actual_bytes_reader.read_be_uint16_t(), raw_value);
    } else if (raw_value <= std::numeric_limits<uint32_t>::max()) {
        ASSERT_EQ(actual_bytes.size(), 5);
        ASSERT_EQ(actual_bytes_reader.read_be_uint32_t(), raw_value);
    } else if (raw_value <= std::numeric_limits<uint64_t>::max()) {
        ASSERT_EQ(actual_bytes.size(), 9);
        ASSERT_EQ(actual_bytes_reader.read_be_uint64_t(), raw_value);
    }

    auto actual_cbor = wfb::parse_cbor<wfb::cbor_integer>(actual_bytes);
    ASSERT_EQ(initial_cbor, actual_cbor);
}

TEST(CBOR, NonNegativeIntegers) {
    // Examples explicitly mentioned by RFC
    {
        std::vector<uint8_t> bytes = {0b000'01010};
        auto actual_value = wfb::parse_cbor<uint8_t>(bytes);
        ASSERT_EQ(actual_value, 10);
    }

    {
        std::vector<uint8_t> bytes = {0b000'11001, 0x01, 0xf4};
        auto actual_value = wfb::parse_cbor<uint16_t>(bytes);
        ASSERT_EQ(actual_value, 500);
    }

    // Integers up to 16-bit are small enough to just brute-force test every
    // possible value
    for (uint64_t num = 0; num < 24; num++) {
        std::array<uint8_t, 1> bytes{static_cast<uint8_t>(num)};
        auto actual_value = wfb::parse_cbor<uint16_t>(bytes);
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

    auto actual_value = wfb::parse_cbor<int64_t>(bytes);
    ASSERT_EQ(actual_value, value);

    if (value >= std::numeric_limits<int64_t>::min() &&
        value <= std::numeric_limits<int64_t>::max()) {
        test_integer_roundtrip((int64_t)value);
    }
}

TEST(CBOR, NegativeIntegers) {
    // Example explicitly mentioned by RFC
    {
        std::vector<uint8_t> bytes = {0b001'11001, 0x01, 0xf3};
        auto actual_value = wfb::parse_cbor<int16_t>(bytes);
        ASSERT_EQ(actual_value, -500);
    }

    // Integers up to 16-bit are small enough to just brute-force test every
    // possible value
    for (int64_t num = -24; num < 0; num++) {
        std::array<uint8_t, 1> bytes{static_cast<uint8_t>(0b00100000 | std::abs(num) - 1)};
        auto actual_value = wfb::parse_cbor<int8_t>(bytes);
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
        EXPECT_THROW(test_negative_integer<8>(0b00100000 | 27, num), std::overflow_error);
    }
}

template <typename T>
void test_integer_comparison_operators() {
    T t_small{50};
    wfb::cbor_integer int_small{50};
    T t_large{100};
    wfb::cbor_integer int_large{100};

    auto test_operators =
        [=](auto&& lhs, auto&& rhs, bool eq, bool ne, bool lt, bool le, bool gt, bool ge) {
            ASSERT_EQ(lhs == rhs, eq);
            ASSERT_EQ(lhs != rhs, ne);
            ASSERT_EQ(lhs < rhs, lt);
            ASSERT_EQ(lhs <= rhs, le);
            ASSERT_EQ(lhs > rhs, gt);
            ASSERT_EQ(lhs >= rhs, ge);
        };

    auto test_small = [=](auto&& small_val) {
        test_operators(small_val, t_small, true, false, false, true, false, true);
        test_operators(small_val, int_small, true, false, false, true, false, true);
        test_operators(small_val, t_large, false, true, true, true, false, false);
        test_operators(small_val, int_large, false, true, true, true, false, false);
    };

    auto test_large = [=](auto&& large_val) {
        test_operators(large_val, t_small, false, true, false, false, true, true);
        test_operators(large_val, int_small, false, true, false, false, true, true);
        test_operators(large_val, t_large, true, false, false, true, false, true);
        test_operators(large_val, int_large, true, false, false, true, false, true);
    };

    test_small(t_small);
    test_small(int_small);
    test_large(t_large);
    test_large(int_large);
}

TEST(CBOR, IntegerComparisonOperators) {
    test_integer_comparison_operators<wfb::cbor_integer>();
    test_integer_comparison_operators<uint8_t>();
    test_integer_comparison_operators<int8_t>();
    test_integer_comparison_operators<uint16_t>();
    test_integer_comparison_operators<int16_t>();
    test_integer_comparison_operators<uint32_t>();
    test_integer_comparison_operators<int32_t>();
    test_integer_comparison_operators<uint64_t>();
    test_integer_comparison_operators<int64_t>();
}
