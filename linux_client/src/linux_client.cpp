#include "binary_io.hpp"
#include "cbor.hpp"
#include "util.hpp"
#include "webauthn.hpp"

#include <windows_fido_bridge/base64.hpp>
#include <windows_fido_bridge/communication.hpp>
#include <windows_fido_bridge/format.hpp>

#include <nlohmann/json.hpp>

extern "C" {

#include "sk-api.h"

}

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>

#include <sys/wait.h>
#include <unistd.h>

using json = nlohmann::json;

extern "C" {

/* Return the version of the middleware API */
uint32_t sk_api_version(void) {
    return SSH_SK_VERSION_MAJOR;
}

/* Enroll a U2F key (private key generation) */
int sk_enroll(uint32_t alg, const uint8_t *challenge, size_t challenge_len,
              const char *application, uint8_t flags, const char *pin,
              struct sk_option **options, struct sk_enroll_response **enroll_response) {
    std::cerr << "In sk_enroll()" << std::endl;

    std::array<int, 2> out_to_child_pipe{};
    pipe(out_to_child_pipe.data());

    std::array<int, 2> in_from_child_pipe{};
    pipe(in_from_child_pipe.data());

    pid_t pid = fork();
    if (pid == -1) {
        std::cerr << "ERROR: failed to fork" << std::endl;
        return SSH_SK_ERR_GENERAL;
    }

    if (pid == 0) {
        // Child
        std::cerr << "In child after fork()" << std::endl;

        // Close the ends of the pipes that we don't need
        close(out_to_child_pipe[1]);
        close(in_from_child_pipe[0]);

        // Replace stdin with the read end of the output pipe
        dup2(out_to_child_pipe[0], fileno(stdin));

        // Replace stdout with the write end of the input pipe
        dup2(in_from_child_pipe[1], fileno(stdout));

        const char* windows_server_path = "/home/mgbowen/windows_fido_bridge/build/windows_server/windows_server/windows_server.exe";
        int result = execl(windows_server_path, nullptr);
        if (result == -1) {
            std::cerr << "FATAL: failed to exec (" << strerror(errno) << ")" << std::endl;
            std::flush(std::cerr);
            std::abort();
        }
    } else {
        // Parent
        std::cerr << "In parent after fork()" << std::endl;

        // Send parameters to child
        json parameters = {
            {"type", "create"},
            {"challenge", base64_encode(reinterpret_cast<const unsigned char*>(challenge), challenge_len)},
            {"application", std::string{application}},
        };

        wfb::send_message(out_to_child_pipe[1], parameters);
        std::string raw_result = wfb::receive_message(in_from_child_pipe[0]);

        pid_t wait_result = waitpid(pid, 0, 0);
        if (wait_result == -1) {
            std::cerr << "ERROR: failed to wait for child to complete" << std::endl;
            return SSH_SK_ERR_GENERAL;
        }

        std::cerr << "Wait result: " << wait_result << std::endl;

        json contents = json::parse(raw_result);

        std::string cred_id = base64_decode(contents["credential_id"].get<std::string>());
        wfb::dump_binary(reinterpret_cast<const uint8_t*>(cred_id.data()), cred_id.size());

        std::string raw_attestation_object = base64_decode(contents["attestation_object"].get<std::string>());
        json attestation_object = json::from_cbor(raw_attestation_object);
        const std::vector<uint8_t>& auth_data_bytes = *attestation_object["authData"].get_ptr<const json::binary_t*>();

        wfb::binary_reader reader{reinterpret_cast<const uint8_t*>(auth_data_bytes.data()), auth_data_bytes.size()};
        wfb::authenticator_data auth_data{reader};
        auth_data.dump();

        auto response = reinterpret_cast<sk_enroll_response*>(calloc(1, sizeof(**enroll_response)));

        response->public_key = reinterpret_cast<uint8_t*>(calloc(1, auth_data.attested_credential->public_key.size()));
        memcpy(response->public_key, auth_data.attested_credential->public_key.data(), auth_data.attested_credential->public_key.size());
        response->public_key_len = auth_data.attested_credential->public_key.size();

        response->key_handle = reinterpret_cast<uint8_t*>(calloc(1, auth_data.attested_credential->id.size()));
        memcpy(response->key_handle, auth_data.attested_credential->id.data(), auth_data.attested_credential->id.size());
        response->key_handle_len = auth_data.attested_credential->id.size();

        wfb::binary_reader reader2{reinterpret_cast<const uint8_t*>(raw_attestation_object.data()), raw_attestation_object.size()};
        auto cbor_attestation_object = wfb::load_cbor(reader2).get<wfb::cbor_map>();
        //cbor_attestation_object.dump();

        auto cbor_att_statement = cbor_attestation_object["attStmt"].get<wfb::cbor_map>();
        cbor_att_statement.dump();

        std::vector<uint8_t> cbor_signature = cbor_att_statement["sig"].get<wfb::cbor_byte_string>();

        response->signature = reinterpret_cast<uint8_t*>(calloc(1, cbor_signature.size()));
        memcpy(response->signature, cbor_signature.data(), cbor_signature.size());
        response->signature_len = cbor_signature.size();

        std::vector<wfb::cbor_value> cbor_x5c_array = cbor_att_statement["x5c"].get<wfb::cbor_array>();
        std::vector<uint8_t> cbor_x5c = cbor_x5c_array[0].get<wfb::cbor_byte_string>();

        response->attestation_cert = reinterpret_cast<uint8_t*>(calloc(1, cbor_x5c.size()));
        memcpy(response->attestation_cert, cbor_x5c.data(), cbor_x5c.size());
        response->attestation_cert_len = cbor_x5c.size();

        *enroll_response = response;
    }

    std::cerr << "Exiting normally\n";

    return 0;
}

/* Sign a challenge */
int sk_sign(uint32_t alg, const uint8_t *message, size_t message_len,
            const char *application, const uint8_t *key_handle, size_t key_handle_len,
            uint8_t flags, const char *pin, struct sk_option **options,
            struct sk_sign_response **sign_response) {
    std::cerr << "In sk_sign()" << std::endl;
    std::cerr << "    flags: {:02x}\n"_format(flags);
    std::cerr << "    message:\n";
    wfb::dump_binary(message, message_len);

    std::array<int, 2> out_to_child_pipe{};
    pipe(out_to_child_pipe.data());

    std::array<int, 2> in_from_child_pipe{};
    pipe(in_from_child_pipe.data());

    pid_t pid = fork();
    if (pid == -1) {
        std::cerr << "ERROR: failed to fork" << std::endl;
        return SSH_SK_ERR_GENERAL;
    }

    if (pid == 0) {
        // Child
        std::cerr << "In child after fork()" << std::endl;

        // Close the ends of the pipes that we don't need
        close(out_to_child_pipe[1]);
        close(in_from_child_pipe[0]);

        // Replace stdin with the read end of the output pipe
        dup2(out_to_child_pipe[0], fileno(stdin));

        // Replace stdout with the write end of the input pipe
        dup2(in_from_child_pipe[1], fileno(stdout));

        const char* windows_server_path = "/home/mgbowen/windows_fido_bridge/build/windows_server/windows_server/windows_server.exe";
        int result = execl(windows_server_path, nullptr);
        if (result == -1) {
            std::cerr << "FATAL: failed to exec (" << strerror(errno) << ")" << std::endl;
            std::flush(std::cerr);
            std::abort();
        }
    } else {
        // Parent
        std::cerr << "In parent after fork()" << std::endl;

        // Send parameters to child
        json parameters = {
            {"type", "sign"},
            {"message", base64_encode(reinterpret_cast<const unsigned char*>(message), message_len)},
            {"application", std::string{application}},
            {"key_handle", base64_encode(reinterpret_cast<const unsigned char*>(key_handle), key_handle_len)},
        };

        wfb::send_message(out_to_child_pipe[1], parameters);
        std::string raw_result = wfb::receive_message(in_from_child_pipe[0]);

        json contents = json::parse(raw_result);
        std::string signature_b64 = contents["signature"];
        std::string signature_str = base64_decode(signature_b64);

        wfb::dump_binary(signature_str);

        std::string authenticator_data_b64 = contents["authenticator_data"];
        std::string authenticator_data_str = base64_decode(authenticator_data_b64);
        wfb::binary_reader authenticator_data_reader{reinterpret_cast<const uint8_t*>(authenticator_data_str.data()), authenticator_data_str.size()};
        wfb::authenticator_data auth_data{authenticator_data_reader};

        std::cerr << "\nAuthenticator data dump:\n";
        auth_data.dump();

        int status;
        pid_t wait_result = waitpid(pid, &status, 0);
        if (wait_result == -1) {
            std::cerr << "ERROR: failed to wait for child to complete" << std::endl;
            return SSH_SK_ERR_GENERAL;
        }

        std::cerr << "Wait result: " << wait_result << ", exit code: " << WEXITSTATUS(status) << std::endl;

        auto response = reinterpret_cast<sk_sign_response*>(calloc(1, sizeof(**sign_response)));

        response->flags = auth_data.flags;
        response->counter = auth_data.signature_count;

        response->sig_r = reinterpret_cast<uint8_t*>(calloc(1, 32));

        char* pos = signature_str.data() + 4;
        if (*pos == 0) {
            pos++;
        }

        memcpy(response->sig_r, pos, 32);
        pos += 32;

        response->sig_r_len = 32;

        std::cerr << "sig_r:\n";
        wfb::dump_binary(response->sig_r, response->sig_r_len);

        response->sig_s = reinterpret_cast<uint8_t*>(calloc(1, 32));

        pos += 2;
        if (*pos == 0) {
            pos++;
        }

        memcpy(response->sig_s, pos, 32);

        response->sig_s_len = 32;

        std::cerr << "sig_s:\n";
        wfb::dump_binary(response->sig_s, response->sig_s_len);

        *sign_response = response;
    }

    return 0;
}

/* Enumerate all resident keys */
int sk_load_resident_keys(const char *pin, struct sk_option **options,
                          struct sk_resident_key ***rks, size_t *nrks) {
    std::cerr << "Hello from sk_load_resident_keys!\n";
    return SSH_SK_ERR_UNSUPPORTED;
}

}  // extern "C"
