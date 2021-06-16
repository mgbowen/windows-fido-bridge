#include <windows_fido_bridge/binary_io.hpp>
#include <windows_fido_bridge/cbor.hpp>
#include <windows_fido_bridge/communication.hpp>
#include <windows_fido_bridge/openssh_sk_middleware.hpp>
#include <windows_fido_bridge/types.hpp>
#include <windows_fido_bridge/util.hpp>

#include <spdlog/spdlog.h>

extern "C" {

#include <sk-api.h>

}

#include <windows.h>
#include <stdio.h>
#include <fcntl.h>
#include <io.h>

#include <array>
#include <cstdint>
#include <iostream>
#include <system_error>
#include <vector>

namespace wfb {

namespace {

constexpr std::string_view LOG_NAME = "win32-bridge";

extern "C" INT WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR lpCmdLine, INT nCmdShow) {
    set_up_logger(LOG_NAME);

    // Set stdin and stdout to binary mode to prevent issues with reading and
    // writing CBOR between us and the Linux bridge.
    int read_fd = _fileno(stdin);
    int write_fd = _fileno(stdout);

    _setmode(read_fd, _O_BINARY);
    _setmode(write_fd, _O_BINARY);

    byte_vector raw_request_message = receive_message(read_fd);
    auto request_message = parse_cbor<cbor_map>(raw_request_message);
    spdlog::debug("Received CBOR from caller: {}", request_message.dump_debug());

    auto request_type = request_message.at<cbor_text_string>("request_type");

    if (request_type == "sk_enroll") {
        const auto& request_parameters = request_message.at<cbor_map>("request_parameters");
        const auto& challenge = request_parameters.at<cbor_byte_string>("challenge");
        const auto& application = request_parameters.at<cbor_text_string>("application");
        std::vector<parsed_sk_option> options = cbor_array_to_parsed_sk_options(
            request_parameters.at<cbor_array>("sk_options")
        );

        int return_code;
        unique_sk_enroll_response_ptr response;

        try {
            std::tie(return_code, response) = sk_enroll_safe(
                request_parameters.at<uint32_t>("alg"),
                challenge.span(),
                application.view(),
                request_parameters.at<uint32_t>("flags"),
                std::string_view{},
                options
            );
        } catch (const std::exception& ex) {
            spdlog::critical("Failed to create WebAuthn assertion: {}", ex.what());
            return_code = SSH_SK_ERR_GENERAL;
        } catch (...) {
            return_code = SSH_SK_ERR_GENERAL;
        }

        auto response_message = cbor_map({
            {"return_code", return_code},
        });

        if (return_code == 0) {
            response_message["response_parameters"] = cbor_map({
                {"public_key", std::span<const uint8_t>(response->public_key, response->public_key_len)},
                {"key_handle", std::span<const uint8_t>(response->key_handle, response->key_handle_len)},
                {"signature", std::span<const uint8_t>(response->signature, response->signature_len)},
                {"attestation_cert", std::span<const uint8_t>(response->attestation_cert, response->attestation_cert_len)},
                {"authdata", std::span<const uint8_t>(response->authdata, response->authdata_len)},
            });
        }

        auto raw_response_message = wfb::dump_cbor(response_message);
        spdlog::debug("Sending CBOR to caller: {}", response_message.dump_debug());
        send_message(write_fd, raw_response_message);
    } else if (request_type == "sk_sign") {
        const auto& request_parameters = request_message.at<cbor_map>("request_parameters");
        const auto& data = request_parameters.at<cbor_byte_string>("data");
        const auto& application = request_parameters.at<cbor_text_string>("application");
        const auto& key_handle = request_parameters.at<cbor_byte_string>("key_handle");
        std::vector<parsed_sk_option> options = cbor_array_to_parsed_sk_options(
            request_parameters.at<cbor_array>("sk_options")
        );

        int return_code;
        unique_sk_sign_response_ptr response;

        try {
            std::tie(return_code, response) = sk_sign_safe(
                request_parameters.at<uint32_t>("alg"),
                data.span(),
                application.view(),
                key_handle.span(),
                request_parameters.at<uint32_t>("flags"),
                std::string_view{},
                options
            );
        } catch (const std::exception& ex) {
            spdlog::critical("Failed to create WebAuthn assertion: {}", ex.what());
            return_code = SSH_SK_ERR_GENERAL;
        } catch (...) {
            return_code = SSH_SK_ERR_GENERAL;
        }

        auto response_message = cbor_map({
            {"return_code", return_code},
        });

        if (return_code == 0) {
            auto response_parameters = cbor_map({
                {"flags", response->flags},
                {"counter", response->counter},
            });

            if (response->sig_r != nullptr) {
                response_parameters["sig_r"] = std::span<const uint8_t>(response->sig_r, response->sig_r_len);
            }

            if (response->sig_s != nullptr) {
                response_parameters["sig_s"] = std::span<const uint8_t>(response->sig_s, response->sig_s_len);
            }

            response_message["response_parameters"] = std::move(response_parameters);
        }

        auto raw_response_message = wfb::dump_cbor(response_message);
        spdlog::debug("Sending CBOR to caller: {}", response_message.dump_debug());
        send_message(write_fd, raw_response_message);
    } else {
        spdlog::critical("Unrecognized type");
        abort();
    }

    return 0;
}

}  // namespace

}  // namespace wfb
