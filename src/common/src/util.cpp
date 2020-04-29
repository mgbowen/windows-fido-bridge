#include "windows_fido_bridge/util.hpp"

#include "windows_fido_bridge/format.hpp"

#include <iostream>

namespace wfb {

namespace {

constexpr const size_t DUMP_BINARY_LINE_LENGTH = 16;

template <typename Output>
void dump_binary_line(Output& output, const uint8_t* buffer, size_t length) {
    // Print hex values
    for (size_t i = 0; i < length; i++) {
        output << "{:02x} "_format(buffer[i]);
    }

    // If we didn't print a full line, print some padding to line up this
    // partial line's ASCII output with the full lines above it
    if (length < DUMP_BINARY_LINE_LENGTH) {
        output << std::string((DUMP_BINARY_LINE_LENGTH - length) * 3, ' ');
    }

    output << ' ';

    // Print ASCII values
    for (size_t i = 0; i < length; i++) {
        char c = buffer[i];
        if (c < 0x20 || c > 0x7e) {
            // Non-printable ASCII, just print a placeholder
            c = '.';
        }

        output << c;
    }

    output << "\n";
}

}  // namespace

void dump_binary(const uint8_t* buffer, size_t length, size_t indent) {
    std::string indent_str(indent, ' ');

    // Printer a header
    std::cerr << indent_str << "      ";
    for (size_t i = 0; i < DUMP_BINARY_LINE_LENGTH; i++) {
        std::cerr << " {:x} "_format(i);
    }

    std::cerr << "\n";

    // Print the values
    for (size_t i = 0; i < length; i += DUMP_BINARY_LINE_LENGTH) {
        std::cerr << indent_str << "{:04x}: "_format(i);

        dump_binary_line(std::cerr, buffer + i, std::min(DUMP_BINARY_LINE_LENGTH, length - i));
    }
}

}  // namespace wfb
