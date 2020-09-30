#include <windows_fido_bridge/binary_io.hpp>
#include <windows_fido_bridge/cbor.hpp>

#include <gtest/gtest.h>

#include <initializer_list>
#include <limits>
#include <vector>

using namespace wfb::literals;

TEST(CBOR, Array) {
    {
        std::vector<uint8_t> bytes = {0b100'01010, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        std::vector<uint8_t> expected_items = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        auto actual_items = static_cast<std::vector<uint8_t>>(wfb::parse_cbor<wfb::cbor_array>(bytes));
        ASSERT_EQ(expected_items, actual_items);
    }

    // Test roundtrip
    {
        wfb::cbor_array expected = {42, -12345, "hello world", "foobar"_bytes};

        wfb::byte_vector bytes = wfb::dump_cbor(expected);
        auto actual = wfb::parse_cbor<wfb::cbor_array>(bytes);

        ASSERT_EQ(expected, actual);
    }
}
