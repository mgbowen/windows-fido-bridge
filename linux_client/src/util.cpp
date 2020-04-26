#include "util.hpp"

#include <windows_fido_bridge/format.hpp>

#include <iostream>

namespace wfb {

void dump_binary(const uint8_t* buffer, size_t length) {
    for (int i = 0; i < length; i++) {
        if (i > 0 && i % 16 == 0) {
            std::cerr << ' ';

            for (int ascii_i = 0; ascii_i < 16; ascii_i++) {
                char c = buffer[((i - 1) / 16 * 16) + ascii_i];
                if (c >= 0x20 && c <= 0x7e) {
                    std::cerr << c;
                } else {
                    std::cerr << '.';
                }
            }

            std::cerr << "\n";
        }

        std::cerr << "{:02x} "_format((uint8_t)buffer[i]);
    }

    std::cerr << "\n";
}

}  // namespace wfb
