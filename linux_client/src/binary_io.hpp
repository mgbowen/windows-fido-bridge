#pragma once

#include <cstdint>
#include <span>
#include <string>

namespace wfb {

class binary_reader {
public:
    binary_reader(std::span<uint8_t> buffer);
};

}  // namespace wfb
