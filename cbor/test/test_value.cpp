#include <windows_fido_bridge/binary_io.hpp>
#include <windows_fido_bridge/cbor.hpp>

#include <gtest/gtest.h>

#include <initializer_list>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

TEST(CBOR, ValueBoxing) {
    // cbor_string
    {
        const char* c_str = "hello world";
        std::string str_obj = "hello world";
        std::string_view str_view = str_obj;

        wfb::cbor_string original_cbor_str{"hello world"};
        ASSERT_EQ(original_cbor_str, c_str);
        // TODO: ASSERT_EQ(c_str, original_cbor_str);
        ASSERT_EQ(original_cbor_str, str_obj);
        // TODO: ASSERT_EQ(str_obj, original_cbor_str);
        ASSERT_EQ(original_cbor_str, str_view);
        // TODO: ASSERT_EQ(str_view, original_cbor_str);

        wfb::cbor_value boxed_cbor_str{original_cbor_str};
        ASSERT_EQ(boxed_cbor_str, original_cbor_str);
        // TODO: ASSERT_EQ(original_cbor_str, boxed_cbor_str);

        auto unboxed_cbor_str = static_cast<wfb::cbor_string>(boxed_cbor_str);
        ASSERT_EQ(unboxed_cbor_str, c_str);
        ASSERT_EQ(unboxed_cbor_str, str_obj);
        ASSERT_EQ(unboxed_cbor_str, str_view);
    }
}

TEST(CBOR, ValueCasting) {
    // cbor_string
    {
        wfb::cbor_string str{"hello world"};
        ASSERT_EQ(str, "hello world");

        wfb::cbor_value boxed_str{str};
        EXPECT_THROW(static_cast<wfb::cbor_integer>(boxed_str), std::runtime_error);
        EXPECT_THROW(static_cast<wfb::cbor_array>(boxed_str), std::runtime_error);
        EXPECT_THROW(static_cast<wfb::cbor_map>(boxed_str), std::runtime_error);
    }
}
