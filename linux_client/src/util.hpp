#pragma once

#include <windows_fido_bridge/types.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace wfb {

template <typename T>
using remove_cvref_t = std::remove_cv_t<std::remove_reference_t<T>>;

template <typename T, typename U>
using enable_if_convertible_without_cvref =
    std::enable_if_t<std::is_convertible_v<remove_cvref_t<T>, remove_cvref_t<U>>, int>;

template <typename T, typename U>
using enable_if_not_convertible_without_cvref =
    std::enable_if_t<! std::is_convertible_v<remove_cvref_t<T>, U>, int>;

template <typename T, typename U>
constexpr bool is_explicitly_convertible =
    std::is_constructible_v<remove_cvref_t<T>, remove_cvref_t<U>> &&
        ! std::is_convertible_v<remove_cvref_t<T>, remove_cvref_t<U>>;

}  // namespace wfb
