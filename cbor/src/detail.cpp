#include "windows_fido_bridge/cbor/detail.hpp"
#include "windows_fido_bridge/cbor/types/integer.hpp"

#include <windows_fido_bridge/binary_io.hpp>

namespace wfb {

std::tuple<uint8_t, uint64_t> read_raw_length(binary_reader& reader) {
    uint8_t initial_byte = reader.read_uint8_t();
    uint8_t type = initial_byte >> 5;
    uint8_t additional_info = initial_byte & 0x1f;

    uint64_t raw_value = 0;

    if (additional_info < 24) {
        raw_value = additional_info;
    } else {
        switch (additional_info) {
            case 24: raw_value = reader.read_uint8_t(); break;
            case 25: raw_value = reader.read_be_uint16_t(); break;
            case 26: raw_value = reader.read_be_uint32_t(); break;
            case 27: raw_value = reader.read_be_uint64_t(); break;
            default:
                throw std::runtime_error(
                    "Invalid additional information value {} for length (initial_byte = 0x{:02x})"_format(
                        additional_info, initial_byte
                    )
                );
        }
    }

    return {type, raw_value};
}

void write_initial_byte_into(binary_writer& writer, uint8_t major_type, uint64_t raw_value) {
    if (major_type > 7) {
        throw std::out_of_range("Invalid major type value");
    }

    uint8_t major_type_shifted = (major_type << 5) & 0b111'00000;
    std::cerr << (int)major_type_shifted << ", " << raw_value << "\n";

    if (raw_value < 24) {
        writer.write_uint8_t(major_type_shifted | raw_value);
    } else if (raw_value <= std::numeric_limits<uint8_t>::max()) {
        writer.write_uint8_t(major_type_shifted | 24);
        writer.write_uint8_t(raw_value);
    } else if (raw_value <= std::numeric_limits<uint16_t>::max()) {
        writer.write_uint8_t(major_type_shifted | 25);
        writer.write_be_uint16_t(raw_value);
    } else if (raw_value <= std::numeric_limits<uint32_t>::max()) {
        writer.write_uint8_t(major_type_shifted | 26);
        writer.write_be_uint32_t(raw_value);
    } else if (raw_value <= std::numeric_limits<uint64_t>::max()) {
        writer.write_uint8_t(major_type_shifted | 27);
        writer.write_be_uint64_t(raw_value);
    } else {
        throw std::runtime_error("Unexpected additional information value");
    }
}

}  // namespace wfb
