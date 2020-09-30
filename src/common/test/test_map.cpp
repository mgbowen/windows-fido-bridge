#include <windows_fido_bridge/binary_io.hpp>
#include <windows_fido_bridge/cbor.hpp>

#include <gtest/gtest.h>

#include <initializer_list>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

using namespace wfb::literals;

TEST(CBOR, Map) {
    {
        std::vector<uint8_t> bytes = {0b101'00100, 0, 1, 2, 3, 4, 5, 6, 7};
        std::map<uint8_t, uint8_t> expected_items = {{0, 1}, {2, 3}, {4, 5}, {6, 7}};
        auto actual_items = static_cast<std::map<uint8_t, uint8_t>>(wfb::parse_cbor<wfb::cbor_map>(bytes));
        ASSERT_EQ(expected_items, actual_items);
    }

    // Test roundtrip
    {
        wfb::cbor_map expected{
            {"hello world", 42},
            {-1, "foobar"_bytes},
        };

        wfb::byte_vector bytes = wfb::dump_cbor(expected);
        auto actual = wfb::parse_cbor<wfb::cbor_map>(bytes);

        ASSERT_EQ(expected, actual);
    }
}

TEST(CBOR, MapInitializerList) {
    wfb::cbor_map map{
        {"hello world", 42},
        {1, "foobar"},
        {wfb::cbor_value{"boxed string"}, -1}
    };

    ASSERT_EQ(map.size(), 3);
    ASSERT_EQ(map["hello world"], 42);
    ASSERT_EQ(map[1], "foobar");
    ASSERT_EQ(map["boxed string"], -1);
}
