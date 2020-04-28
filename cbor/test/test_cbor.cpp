#include <windows_fido_bridge/binary_io.hpp>
#include <windows_fido_bridge/cbor.hpp>

#include <gtest/gtest.h>

#include <initializer_list>
#include <limits>
#include <vector>

TEST(CBOR, ByteStrings) {
    // Examples explicitly mentioned by RFC
    {
        std::vector<uint8_t> bytes = {0b010'00101, 'a', 'b', 'c', 'd', 'e'};
        std::vector<uint8_t> expected_bytes = {'a', 'b', 'c', 'd', 'e'};
        std::vector<uint8_t> actual_bytes = wfb::parse_cbor<wfb::cbor_string>(bytes);
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

        std::vector<uint8_t> actual_byte_string = wfb::parse_cbor<wfb::cbor_string>(bytes);
        ASSERT_EQ(actual_byte_string, expected_byte_string);
    }
}

TEST(CBOR, Arrays) {
    {
        std::vector<uint8_t> bytes = {0b100'01010, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        std::vector<uint8_t> expected_items = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        auto actual_items = static_cast<std::vector<uint8_t>>(wfb::parse_cbor<wfb::cbor_array>(bytes));
        ASSERT_EQ(expected_items, actual_items);
    }
}

TEST(CBOR, Maps) {
    std::vector<uint8_t> bytes = {0b101'00100, 0, 1, 2, 3, 4, 5, 6, 7};
    std::map<uint8_t, uint8_t> expected_items = {{0, 1}, {2, 3}, {4, 5}, {6, 7}};
    auto actual_items = static_cast<std::map<uint8_t, uint8_t>>(wfb::parse_cbor<wfb::cbor_map>(bytes));
    ASSERT_EQ(expected_items, actual_items);
}
