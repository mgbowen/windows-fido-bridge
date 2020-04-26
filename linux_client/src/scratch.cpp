#include "binary_io.hpp"
#include "webauthn.hpp"
#include "util.hpp"

#include <windows_fido_bridge/base64.hpp>

#include <nlohmann/json.hpp>

#include <fstream>
#include <iomanip>
#include <iostream>

int main() {
    using namespace wfb;

    std::string raw_contents;

    {
        std::ifstream in("/home/mgbowen/windows_fido_bridge/sample_output.json", std::ios::in | std::ios::binary);
        if (!in) {
            std::cerr << "ERROR: failed to open file\n";
            return 1;
        }

        in.seekg(0, std::ios::end);
        raw_contents.resize(in.tellg());
        in.seekg(0, std::ios::beg);
        in.read(&raw_contents[0], raw_contents.size());
    }

    json contents = json::parse(raw_contents);
    std::string raw_attestation_object = wfb::base64_decode(contents["attestation_object"].get<std::string>());

    std::cerr << "Raw attestation object bytes:\n";
    dump_binary(raw_attestation_object);
    std::cerr << "\n";

    json attestation_object = json::from_cbor(raw_attestation_object);
    const std::vector<uint8_t>& auth_data_bytes = *attestation_object["authData"].get_ptr<const json::binary_t*>();

    binary_reader reader2{reinterpret_cast<const uint8_t*>(raw_attestation_object.data()), raw_attestation_object.size()};
    load_cbor(reader2).dump();

    std::cerr << "Raw auth data bytes:\n";
    dump_binary(auth_data_bytes);
    std::cerr << "\n";

    binary_reader reader{reinterpret_cast<const uint8_t*>(auth_data_bytes.data()), auth_data_bytes.size()};
    authenticator_data auth_data{reader};
    auth_data.dump();

    return 0;
}
