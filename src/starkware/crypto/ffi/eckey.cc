//
// Created by xyz on 2022/5/16.
//

#include "starkware/crypto/ffi/eckey.h"
#include "starkware/crypto/eckey.h"

#include <array>

#include "third_party/gsl/gsl-lite.hpp"

#include "starkware/algebra/prime_field_element.h"
#include "starkware/crypto/ffi/utils.h"

namespace starkware {

    namespace {

        using ValueType = PrimeFieldElement::ValueType;

        constexpr size_t kElementSize = sizeof(ValueType);
        constexpr size_t kPubkeySize = sizeof(ValueType) * 2;
        constexpr size_t kMaxPubkeySize = sizeof(ValueType) * 2 + 1;

        constexpr size_t kOutBufferSize = 1024;
        static_assert(kOutBufferSize >= kElementSize, "kOutBufferSize is not big enough");

    }  // namespace

    extern "C" int SeckeyValidate(const gsl::byte private_key[kElementSize], gsl::byte out[kElementSize]) {
        try {
            const auto bytes = Deserialize(gsl::make_span(private_key, kElementSize));
            auto is_valid =  SeckeyValidate(bytes);
            return is_valid ? 0 : 1;
        } catch (const std::exception &e) {
            return HandleError(e.what(), gsl::make_span(out, kOutBufferSize));
        } catch (...) {
            return HandleError("Unknown c++ exception.", gsl::make_span(out, kOutBufferSize));
        }
//        return 0;
    }

    extern "C" int SeckeyNegate(
            const gsl::byte private_key[kElementSize], gsl::byte out[kElementSize]) {
        try {
            const auto bytes = Deserialize(gsl::make_span(private_key, kElementSize));
            auto prv_key = SeckeyNegate(bytes);
            Serialize(prv_key, gsl::make_span(out, kElementSize));
        } catch (const std::exception &e) {
            return HandleError(e.what(), gsl::make_span(out, kOutBufferSize));
        } catch (...) {
            return HandleError("Unknown c++ exception.", gsl::make_span(out, kOutBufferSize));
        }
        return 0;
    }

    extern "C" int SeckeyInvert(
            const gsl::byte private_key[kElementSize], gsl::byte out[kElementSize]) {
        try {
            const auto bytes = Deserialize(gsl::make_span(private_key, kElementSize));
            auto prv_key = SeckeyInvert(bytes);
            Serialize(prv_key, gsl::make_span(out, kElementSize));
        } catch (const std::exception &e) {
            return HandleError(e.what(), gsl::make_span(out, kOutBufferSize));
        } catch (...) {
            return HandleError("Unknown c++ exception.", gsl::make_span(out, kOutBufferSize));
        }
        return 0;
    }

    extern "C" int SeckeyTweakAdd(
            const gsl::byte private_key[kElementSize], const gsl::byte other_key[kElementSize],
            gsl::byte out[kElementSize]) {
        try {
            const auto prv_key_bytes = Deserialize(gsl::make_span(private_key, kElementSize));
            const auto other_key_bytes = Deserialize(gsl::make_span(other_key, kElementSize));

            auto new_prv_key = SeckeyTweakAdd(prv_key_bytes, other_key_bytes);
            Serialize(new_prv_key, gsl::make_span(out, kElementSize));
        } catch (const std::exception &e) {
            return HandleError(e.what(), gsl::make_span(out, kOutBufferSize));
        } catch (...) {
            return HandleError("Unknown c++ exception.", gsl::make_span(out, kOutBufferSize));
        }
        return 0;
    }

    extern "C" int SeckeyTweakMul(
            const gsl::byte private_key[kElementSize], const gsl::byte other_key[kElementSize],
            gsl::byte out[kElementSize]) {
        try {
            const auto prv_key_bytes = Deserialize(gsl::make_span(private_key, kElementSize));
            const auto other_key_bytes = Deserialize(gsl::make_span(other_key, kElementSize));

            auto new_prv_key = SeckeyTweakMul(prv_key_bytes, other_key_bytes);
            Serialize(new_prv_key, gsl::make_span(out, kElementSize));
        } catch (const std::exception &e) {
            return HandleError(e.what(), gsl::make_span(out, kOutBufferSize));
        } catch (...) {
            return HandleError("Unknown c++ exception.", gsl::make_span(out, kOutBufferSize));
        }
        return 0;
    }

    extern "C" int PubkeyParse(
            const gsl::byte pub[kMaxPubkeySize], size_t size, gsl::byte out[kPubkeySize]) {
        try {
            auto pub_key = gsl::make_span(pub, size);

            auto new_pub_key = PubkeyParse(pub_key).value();
            SerializePubkey(new_pub_key, gsl::make_span(out, kPubkeySize));
        } catch (const std::exception &e) {
            return HandleError(e.what(), gsl::make_span(out, kOutBufferSize));
        } catch (...) {
            return HandleError("Unknown c++ exception.", gsl::make_span(out, kOutBufferSize));
        }
        return 0;
    }

    extern "C" int PubkeyNegate(
            const gsl::byte pub[kPubkeySize],
            gsl::byte out[kPubkeySize]) {
        try {

            auto new_pub_key = PubkeyNegate(gsl::make_span(pub, kPubkeySize));
            SerializePubkey(new_pub_key, gsl::make_span(out, kPubkeySize));
        } catch (const std::exception &e) {
            return HandleError(e.what(), gsl::make_span(out, kOutBufferSize));
        } catch (...) {
            return HandleError("Unknown c++ exception.", gsl::make_span(out, kOutBufferSize));
        }
        return 0;
    }

    extern "C" int PubkeyTweakAdd(
            const gsl::byte pub[kPubkeySize],
            const gsl::byte other[kPubkeySize],
            gsl::byte out[kPubkeySize]
    ) {
        try {
            auto new_pub_key = PubkeyAdd(gsl::make_span(pub, kPubkeySize), gsl::make_span(other, kPubkeySize));
            SerializePubkey(new_pub_key, gsl::make_span(out, kPubkeySize));
        } catch (const std::exception &e) {
            return HandleError(e.what(), gsl::make_span(out, kOutBufferSize));
        } catch (...) {
            return HandleError("Unknown c++ exception.", gsl::make_span(out, kOutBufferSize));
        }
        return 0;
    }

    extern "C" int PubkeyTweakMul(
            const gsl::byte pub[kPubkeySize],
            const gsl::byte private_key[kElementSize],
            gsl::byte out[kPubkeySize]) {
        try {
            const auto bytes = Deserialize(gsl::make_span(private_key, kElementSize));
            auto new_pub_key = PubkeyMul(gsl::make_span(pub, kPubkeySize), bytes);
            SerializePubkey(new_pub_key, gsl::make_span(out, kPubkeySize));
        } catch (const std::exception &e) {
            return HandleError(e.what(), gsl::make_span(out, kOutBufferSize));
        } catch (...) {
            return HandleError("Unknown c++ exception.", gsl::make_span(out, kOutBufferSize));
        }
        return 0;
    }

}  // namespace starkware
