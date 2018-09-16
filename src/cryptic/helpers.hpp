#pragma once
#include <limits>

namespace cryptic {

template<typename Integer>
constexpr std::byte narrow(Integer number)
{
    static_assert(std::is_integral_v<Integer>);
    static_assert(std::numeric_limits<std::byte>::digits < std::numeric_limits<Integer>::digits);
    return static_cast<std::byte>(number);
}

template<size_t Rotation, typename Unsigned>
constexpr Unsigned rightrotate(Unsigned number)
{
    static_assert(std::is_unsigned_v<Unsigned>);
    constexpr auto bits = std::numeric_limits<Unsigned>::digits;
    static_assert(Rotation <= bits);
    return (number >> Rotation) bitor (number << (bits - Rotation));
}

template<size_t Rotation, typename Unsigned>
constexpr Unsigned leftrotate(Unsigned number)
{
    static_assert(std::is_unsigned_v<Unsigned>);
    constexpr auto bits = std::numeric_limits<Unsigned>::digits;
    static_assert(Rotation <= bits);
    return (number << Rotation) bitor (number >> (bits - Rotation));
}

} // namespace cryptic
