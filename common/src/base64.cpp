#include "windows_fido_bridge/base64.hpp"

#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string.hpp>

//
// Loosely based on https://stackoverflow.com/a/10973348
//

namespace wfb {

std::string base64_encode(const uint8_t* buffer, size_t length) {
    using base64_encoder_it =
        boost::archive::iterators::base64_from_binary<
            boost::archive::iterators::transform_width<const uint8_t*, 6, 8>
        >;

    std::string base64_encoded;

    // Reserve the total number of bytes we'll need after the encoding
    // Based on https://stackoverflow.com/a/4715480
    base64_encoded.resize((length + 2) / 3 * 4);

    std::copy(base64_encoder_it(buffer), base64_encoder_it(buffer + length), base64_encoded.begin());

    // Add padding characters to get the final string to be a length that's a
    // multiple of 3
    size_t num_padding_characters = (3 - (length % 3)) % 3;
    for (size_t i = 0; i < num_padding_characters; i++) {
        base64_encoded[base64_encoded.size() - i - 1] = '=';
    }

    return base64_encoded;
}

std::string base64_decode(const std::string& str) {
    return base64_decode(reinterpret_cast<const uint8_t*>(str.data()), str.size());
}

std::string base64_decode(const uint8_t* buffer, size_t length) {
    using base64_decoder_it =
        boost::archive::iterators::transform_width<
            boost::archive::iterators::binary_from_base64<const uint8_t*>, 8, 6
        >;

    // Determine the number of padding characters at the end of the string
    uint32_t num_padding_characters = 0;
    for (size_t offset_i = 0; offset_i < length; offset_i++) {
        size_t buffer_i = length - offset_i - 1;
        if (buffer[buffer_i] == '=') {
            num_padding_characters++;
        } else {
            break;
        }
    }

    std::string base64_decoded{base64_decoder_it(buffer), base64_decoder_it(buffer + length)};

    // Remove the padding bytes
    base64_decoded.erase(base64_decoded.end() - num_padding_characters, base64_decoded.end());

    return base64_decoded;
}

}  // namespace wfb
