#include <windows_fido_bridge/binary_io.hpp>
#include <windows_fido_bridge/cbor.hpp>

#include <gtest/gtest.h>

#include <initializer_list>
#include <limits>
#include <vector>

using namespace wfb::literals;

TEST(CBOR, ByteStrings) {
    // Examples explicitly mentioned by RFC
    {
        std::vector<uint8_t> bytes = {0b010'00101, 'a', 'b', 'c', 'd', 'e'};
        std::vector<uint8_t> expected_bytes = {'a', 'b', 'c', 'd', 'e'};
        auto actual_cbor_byte_string = wfb::parse_cbor<wfb::cbor_byte_string>(bytes);
        auto actual_string = actual_cbor_byte_string.string();
        auto actual_vector = actual_cbor_byte_string.vector();
        ASSERT_EQ(actual_string, "abcde"_bytes);
        ASSERT_EQ(actual_vector, expected_bytes);
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

        std::vector<uint8_t> actual_byte_string = wfb::parse_cbor<wfb::cbor_byte_string>(bytes);
        ASSERT_EQ(actual_byte_string, expected_byte_string);
    }

    // Test roundtrip
    {
        constexpr size_t expected_str_length = 884;
        std::string expected_str_chars;
        for (int i = 0; i < expected_str_length; i++) {
            expected_str_chars.push_back(i % 256);
        }

        wfb::byte_string expected_str{expected_str_chars.cbegin(), expected_str_chars.cend()};

        wfb::binary_writer writer;
        wfb::write_initial_byte_into(writer, wfb::CBOR_BYTE_STRING, expected_str.size());
        writer.write_string(expected_str);
        wfb::byte_vector expected = writer.vector();

        wfb::cbor_byte_string cbor{wfb::byte_string(expected_str.cbegin(), expected_str.cend())};
        wfb::byte_vector actual = wfb::dump_cbor(cbor);
        ASSERT_EQ(expected, actual);
    }
}
