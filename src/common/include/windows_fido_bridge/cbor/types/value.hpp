#pragma once

#include <windows_fido_bridge/cbor/types/array.hpp>
#include <windows_fido_bridge/cbor/types/integer.hpp>
#include <windows_fido_bridge/cbor/types/map.hpp>
#include <windows_fido_bridge/cbor/types/null.hpp>
#include <windows_fido_bridge/cbor/types/string.hpp>

#include <windows_fido_bridge/exceptions.hpp>
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

enum class cbor_value_type {
    integer,
    byte_string,
    text_string,
    array,
    map,
    null,
    unknown,
};

struct cbor_value_type_discoverer {
    cbor_value_type operator()(const cbor_integer& value) const { return cbor_value_type::integer; }
    cbor_value_type operator()(const cbor_byte_string& value) const { return cbor_value_type::byte_string; }
    cbor_value_type operator()(const cbor_text_string& value) const { return cbor_value_type::text_string; }
    cbor_value_type operator()(const cbor_array& value) const { return cbor_value_type::array; }
    cbor_value_type operator()(const cbor_map& value) const { return cbor_value_type::map; }
    cbor_value_type operator()(const cbor_null& value) const { return cbor_value_type::null; }
};

// Based on https://stackoverflow.com/a/45898325
template <typename T, typename... VariantTypes>
struct is_convertible_to_variant_alternative_type;

template <typename T, typename... VariantTypes>
struct is_convertible_to_variant_alternative_type<T, std::variant<VariantTypes...>> {
    static constexpr bool value = (std::is_convertible_v<remove_cvref_t<T>, remove_cvref_t<VariantTypes>> || ...);
};

template <typename T, typename... VariantTypes>
inline constexpr bool is_convertible_to_variant_alternative_type_v =
    is_convertible_to_variant_alternative_type<T, VariantTypes...>::value;

class cbor_value {
public:
    using storage_type = std::variant<
        cbor_integer,
        cbor_byte_string,
        cbor_text_string,
        cbor_array,
        cbor_map,
        cbor_null
    >;

    cbor_value() : _storage(cbor_null{}) {}

    template <typename T, std::enable_if_t<is_convertible_to_variant_alternative_type_v<T, storage_type>, int> = 0>
    cbor_value(T&& value) : _storage(std::forward<T>(value)) {}

    COPYABLE(cbor_value);
    MOVABLE(cbor_value);

    void dump_cbor_into(binary_writer& writer) const;

    template <typename T>
    T get() const {
        return std::visit(cbor_value_converter<T, storage_type>{}, _storage);
    }

    cbor_value_type type() const {
        return std::visit(cbor_value_type_discoverer{}, _storage);
    }

    std::string dump_debug() const;
    void dump_debug(std::stringstream& ss) const;

    template <typename T> explicit operator T() const { return get<T>(); }

    bool operator==(const cbor_value& rhs) const;
    bool operator<(const cbor_value& rhs) const;

private:
    storage_type _storage;
};

}  // namespace wfb
