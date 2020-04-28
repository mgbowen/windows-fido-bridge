#pragma once

#include <array>
#include <cstdint>
#include <vector>

namespace wfb {

using byte_vector = std::vector<uint8_t>;

template <size_t N>
using byte_array = std::array<uint8_t, N>;

}  // namespace wfb
