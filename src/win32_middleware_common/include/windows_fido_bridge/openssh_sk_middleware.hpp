#pragma once

#include <windows_fido_bridge/openssh.hpp>

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <tuple>

namespace wfb {

std::tuple<int, unique_sk_enroll_response_ptr> sk_enroll_safe(
    uint32_t alg,
    std::span<const uint8_t> challenge,
    std::string_view application,
    uint8_t flags,
    std::string_view pin,
    std::span<const parsed_sk_option> sk_options
);

std::tuple<int, unique_sk_sign_response_ptr> sk_sign_safe(
    uint32_t alg,
    std::span<const uint8_t> data_bytes,
    std::string_view application,
    std::span<const uint8_t> key_handle_bytes,
    uint8_t flags,
    std::string_view pin,
    std::span<const parsed_sk_option> sk_options
);

}  // namespace wfb
