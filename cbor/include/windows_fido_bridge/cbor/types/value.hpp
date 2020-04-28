#pragma once

#include <windows_fido_bridge/cbor/types/array.hpp>
#include <windows_fido_bridge/cbor/types/integer.hpp>
#include <windows_fido_bridge/cbor/types/map.hpp>
#include <windows_fido_bridge/cbor/types/string.hpp>

#include <windows_fido_bridge/util.hpp>

#include <type_traits>
#include <variant>

namespace wfb {

template <typename TDestination, typename TVariant, size_t... TVariantAlternativeTypeIs>
constexpr bool is_convertible_from_variant_alternative_type_helper(
    std::index_sequence<TVariantAlternativeTypeIs...>
) {
    return (std::is_convertible_v<std::variant_alternative_t<TVariantAlternativeTypeIs, TVariant>, TDestination> || ...);
}

template <typename TDestination, typename TVariant, typename Indices = std::make_index_sequence<std::variant_size_v<TVariant>>>
constexpr bool is_convertible_from_variant_alternative_type() {
    return is_convertible_from_variant_alternative_type_helper<TDestination, TVariant>(
        Indices{}
    );
}

template <typename TDestination, typename TVariant>
struct cbor_value_converter {
    template <typename TSource, enable_if_convertible_without_cvref<TSource, TDestination> = 0>
    TDestination operator()(const TSource& value) const {
        return value;
    }

    template <typename TSource,
        std::enable_if_t<
            ! std::is_convertible_v<remove_cvref_t<TSource>, TDestination> &&
                is_convertible_from_variant_alternative_type<TDestination, TVariant>(),
            int
        > = 0>
    TDestination operator()(const TSource& value) const {
        throw std::runtime_error("Bad type cast");
    }
};

// Based on https://stackoverflow.com/a/45898325
template <class T, class VariantTypes>
constexpr bool is_convertible_to_variant_alternative_type;

template <class T, class... VariantTypes>
constexpr bool is_convertible_to_variant_alternative_type<T, std::variant<VariantTypes...>> =
    (std::is_convertible_v<remove_cvref_t<T>, remove_cvref_t<VariantTypes>> || ...);

class cbor_value {
public:
    using storage_type = std::variant<
        cbor_integer,
        cbor_string,
        cbor_array,
        cbor_map
    >;

    template <typename T, std::enable_if_t<is_convertible_to_variant_alternative_type<T, storage_type>, int> = 0>
    cbor_value(T&& value) : _storage(std::forward<T>(value)) {}

    COPYABLE(cbor_value);
    MOVABLE(cbor_value);

    template <typename T>
    T get() const {
        return std::visit(cbor_value_converter<T, storage_type>{}, _storage);
    }

    void dump() const;
    void dump(std::stringstream& ss) const;

    template <typename T> explicit operator T() const { return get<T>(); }

    bool operator==(const cbor_value& rhs) const;
    bool operator<(const cbor_value& rhs) const;

private:
    storage_type _storage;
};

}  // namespace wfb
