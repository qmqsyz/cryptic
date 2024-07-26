#pragma once
#include <concepts>
#include <limits>
#include <gsl/assert.hpp>

namespace cryptic {

template <std::unsigned_integral I>
inline
constexpr I rotr(I i, unsigned n) noexcept
{
    Expects(n < std::numeric_limits<I>::digits);
    return (i >> n) | (i << (std::numeric_limits<I>::digits - n));
}

template <std::unsigned_integral I>
inline
constexpr I rotl(I i, unsigned n) noexcept
{
    Expects(n < std::numeric_limits<I>::digits);
    return (i << n) | (i >> (std::numeric_limits<I>::digits - n));
}

}
