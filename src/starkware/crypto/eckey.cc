//
// Created by xyz on 2022/5/12.
//

#include "starkware/crypto/eckey.h"


#include "starkware/algebra/fraction_field_element.h"
#include "starkware/crypto/elliptic_curve_constants.h"
#include "starkware/utils/error_handling.h"
#include "starkware/utils/prng.h"
#include "third_party/gsl/gsl-lite.hpp"


namespace starkware {


    static constexpr ValueType kModulus =
            0x800000000000010FFFFFFFFFFFFFFFFB781126DCAE7B2321E66A241ADC64D2F_Z;

    bool SeckeyValidate(const PrimeFieldElement::ValueType &private_key) {
        return private_key > PrimeFieldElement::ValueType::Zero() && private_key < PrimeFieldElement::kModulus;
    }

    ValueType SeckeyNegate(const ValueType &private_key) {
        return kModulus-private_key;
    }

    ValueType SeckeyInvert(const ValueType &private_key) {
        return private_key.InvModPrime(kModulus);
    }

    ValueType
    SeckeyTweakAdd(const ValueType &private_key, const ValueType &other_key) {
        return ValueType::ReduceIfNeeded(private_key + other_key, kModulus);
    }

    ValueType
    SeckeyTweakMul(const ValueType &private_key, const ValueType &other_key) {
//        const auto self = PrimeFieldElement::FromBigInt(private_key);
//        const auto other = PrimeFieldElement::FromBigInt(other_key);
        return PrimeFieldElement::ValueType::MulMod(private_key, other_key, kModulus);

    }

    std::optional<EcPoint<PrimeFieldElement>>
    GetPointFromXBytes(const std::array<uint64_t, PrimeFieldElement::ValueType::LimbCount()> bytes) {
        const auto value = PrimeFieldElement::ValueType(bytes);

        const auto public_key_x = PrimeFieldElement::FromBigInt(value);

        const auto alpha = GetEcConstants().k_alpha;
        const auto beta = GetEcConstants().k_beta;
        const auto public_key = EcPoint<PrimeFieldElement>::GetPointFromX(public_key_x, alpha, beta);
        return public_key;
    }

    std::optional<EcPoint<PrimeFieldElement>> PubkeyParse(const gsl::span<const gsl::byte> pub) {
        const auto N = PrimeFieldElement::ValueType::LimbCount();
        if (pub.size() == 33) {
            std::array<uint64_t, N> value_bytes{};
            gsl::copy(pub.subspan(1, sizeof(uint64_t) * N), gsl::byte_span(value_bytes));
            const auto public_key_opt = GetPointFromXBytes(value_bytes);
            if (public_key_opt.has_value()) {
                auto pub_key = public_key_opt.value();
                if ((int)gsl::at(pub, 0) == 3) {
                    auto y_value = pub_key.y.ToStandardForm()[0];

                    if ((pub_key.y.ToStandardForm()[0] & 1ull) == 1ull) {
                        return public_key_opt;
                    } else {
                        return {{pub_key.x, -pub_key.y}};
                    }
                }
                if ((int)gsl::at(pub, 0) == 2) {
                    auto y_value = pub_key.y.ToStandardForm()[0];
                    if ((pub_key.y.ToStandardForm()[0] & 1ull) == 0ull) {
                        return public_key_opt;
                    } else {
                        return {{pub_key.x, -pub_key.y}};
                    }
                }
            }
            return std::nullopt;
        } else {

            auto offset = pub.size() == 65 ? 1 : 0;
            std::array<uint64_t, N> x_value_bytes{};
            std::array<uint64_t, N> y_value_bytes{};

            gsl::copy(pub.subspan(offset, sizeof(uint64_t) * N), gsl::byte_span(x_value_bytes));
            gsl::copy(pub.subspan(offset + 32, sizeof(uint64_t) * N), gsl::byte_span(y_value_bytes));
//            memcpy(&x_value_bytes, pub + offset, 32);
//            memcpy(&y_value_bytes, pub + 32 + offset, 32);


            const auto public_key_opt = GetPointFromXBytes(x_value_bytes);
            if (!public_key_opt.has_value()) return std::nullopt;
            auto public_key = public_key_opt.value();
            const auto y_value = PrimeFieldElement::ValueType(y_value_bytes);
            const auto y_element = PrimeFieldElement::FromBigInt(y_value);

            if (y_element == public_key.y) {
                return public_key_opt;
            } else if (y_element == -public_key.y) {
                return {{public_key.x, -public_key.y}};
            } else {
                return std::nullopt;
            }
        }
    }

    EcPoint<PrimeFieldElement> PubkeyNegate(const gsl::span<const gsl::byte> pub) {
        const auto pubkey = PubkeyParse(pub).value();
        const auto new_pubkey = EcPoint<PrimeFieldElement>(pubkey.x, -pubkey.y);
        return new_pubkey;
    }

    EcPoint<PrimeFieldElement> PubkeyAdd(const gsl::span<const gsl::byte> pub, const gsl::span<const gsl::byte> other) {
        const auto pubkey = PubkeyParse(pub).value();
        const auto other_pubkey = PubkeyParse(other).value();
        if (pubkey.x == other_pubkey.x) {
            if (pubkey.y == other_pubkey.y) {
                const auto& alpha = GetEcConstants().k_alpha;
                return pubkey.Double(alpha);
            } else {
                return EcPoint<PrimeFieldElement>(PrimeFieldElement::Zero(), PrimeFieldElement::Zero());
            }
        }

        return pubkey + other_pubkey;
    }

    EcPoint<PrimeFieldElement>
    PubkeyMul(const gsl::span<const gsl::byte> pub, const PrimeFieldElement::ValueType &private_key) {
        const auto pubkey = PubkeyParse(pub).value();
        const auto &alpha = GetEcConstants().k_alpha;
        const auto ret = pubkey.MultiplyByScalar(private_key, alpha);
        return ret;
    }

}  // namespace starkware