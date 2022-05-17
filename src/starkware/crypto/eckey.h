//
// Created by xyz on 2022/5/12.
//

#ifndef STARKWARECRYPTOLIB_ECKEY_H
#define STARKWARECRYPTOLIB_ECKEY_H


#include <utility>

#include "starkware/algebra/elliptic_curve.h"
#include "starkware/algebra/prime_field_element.h"
#include "third_party/gsl/gsl-lite.hpp"


namespace starkware {

    PrimeFieldElement SeckeyNegate(const PrimeFieldElement::ValueType &private_key);

    PrimeFieldElement
    SeckeyTweakAdd(const PrimeFieldElement::ValueType &private_key, const PrimeFieldElement::ValueType &other_key);

    PrimeFieldElement
    SeckeyTweakMul(const PrimeFieldElement::ValueType &private_key, const PrimeFieldElement::ValueType &other_key);

    std::optional<EcPoint<PrimeFieldElement>>
    GetPointFromXBytes(const std::array<uint64_t, PrimeFieldElement::ValueType::LimbCount()> bytes);

    std::optional<EcPoint<PrimeFieldElement>> PubkeyParse(const gsl::span<const gsl::byte> pub);

    EcPoint<PrimeFieldElement> PubkeyNegate(const gsl::span<const gsl::byte> pub);

    EcPoint<PrimeFieldElement> PubkeyAdd(const gsl::span<const gsl::byte> pub, const gsl::span<const gsl::byte> other);

    EcPoint<PrimeFieldElement>
    PubkeyMul(const gsl::span<const gsl::byte> pub, const PrimeFieldElement::ValueType &private_key);


}  // namespace starkware

#endif //STARKWARECRYPTOLIB_ECKEY_H
