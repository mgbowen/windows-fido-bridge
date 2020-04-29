#pragma once

// Use fmt as a header-only library to make it easier to use when
// cross-compiling with MinGW
#define FMT_HEADER_ONLY
#include <fmt/format.h>

using namespace fmt::literals;
