#pragma once
#include <array>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include "gsl/span.hpp"
#include "gsl/assert.hpp"
#include "cryptic/base64.hpp"

namespace cryptic {

using namespace std;
using namespace gsl;

class sha256
{
public:

    sha256() noexcept :
        m_message_digest{0x6a09e667u,
                         0xbb67ae85u,
                         0x3c6ef372u,
                         0xa54ff53au,
                         0x510e527fu,
                         0x9b05688cu,
                         0x1f83d9abu,
                         0x5be0cd19u},
        m_message_length{0ull},
        m_buffer{}
    {}

    sha256(span<const byte> message) : sha256()
    {
        hash(message);
    }

    void hash(span<const byte> message)
    {
        m_message_digest= {0x6a09e667u,
                           0xbb67ae85u,
                           0x3c6ef372u,
                           0xa54ff53au,
                           0x510e527fu,
                           0x9b05688cu,
                           0x1f83d9abu,
                           0x5be0cd19u};

        m_message_length += 8 * message.size();

        while(message.size() >= 64)
        {
            const auto chunk = message.subspan(0, 64);
            transform(chunk);
            message = message.subspan<64>();
        }

        auto chunk = array<byte,64>{};
        auto itr = copy(message.cbegin(), message.cend(), chunk.begin());
        *itr++ = byte{0b10000000};
        fill(itr, chunk.end(), byte{0b00000000});

        if(distance(chunk.begin(), itr) < 56)
        {
            auto length = make_span(chunk).subspan<56>();
            encode(length, m_message_length);
            transform(chunk);
        }
        else
        {
            transform(chunk);
            fill(chunk.begin(), itr, byte{0b00000000});
            auto length = make_span(chunk).subspan<56>();
            encode(length, m_message_length);
            transform(chunk);
        }
    }

    const byte* data() noexcept
    {
        encode(m_buffer, m_message_digest);
        return m_buffer.data();
    }

    constexpr size_t size() const noexcept
    {
        return m_buffer.size();
    }

    string base64()
    {
        return base64::encode(make_span(data(), size()));
    }

    static string base64(span<const byte> message)
    {
        auto hash = sha256{message};
        return hash.base64();
    }

    string hexadecimal()
    {
        auto ss = stringstream{};
        ss << setw(8) << setfill('0') << hex << m_message_digest[0]
           << setw(8) << setfill('0') << hex << m_message_digest[1]
           << setw(8) << setfill('0') << hex << m_message_digest[2]
           << setw(8) << setfill('0') << hex << m_message_digest[3]
           << setw(8) << setfill('0') << hex << m_message_digest[4]
           << setw(8) << setfill('0') << hex << m_message_digest[5]
           << setw(8) << setfill('0') << hex << m_message_digest[6]
           << setw(8) << setfill('0') << hex << m_message_digest[7];
        return ss.str();
    }

    static string hexadecimal(span<const byte> message)
    {
        auto hash = sha256{message};
        return hash.hexadecimal();
    }

private:

    template<size_t Rotation, typename Unsigned>
    static constexpr Unsigned rightrotate(Unsigned number)
    {
        static_assert(is_unsigned_v<Unsigned>);
        constexpr auto bits = numeric_limits<Unsigned>::digits;
        static_assert(Rotation <= bits);
        return (number >> Rotation) bitor (number << (bits-Rotation));
    }

    void transform(span<const byte> chunk) noexcept
    {
        Expects(chunk.size() == 64);

        auto words = array<uint32_t,64>{};

        for(auto i = 0u, j = 0u; i < 16u; ++i, j += 4u)
            words[i] = to_integer<uint32_t>(chunk[j+0]) << 24 xor
                       to_integer<uint32_t>(chunk[j+1]) << 16 xor
                       to_integer<uint32_t>(chunk[j+2]) <<  8 xor
                       to_integer<uint32_t>(chunk[j+3]);

        for(auto i = 16u; i < 64u; ++i)
        {
            const auto s0 = rightrotate<7>(words[i-15]) xor rightrotate<18>(words[i-15]) xor rightrotate<3>(words[i-15]);
            const auto s1 = rightrotate<17>(words[i-2]) xor rightrotate<19>(words[i-2]) xor rightrotate<10>(words[i-2]);
            words[i] = words[i-16] + s0 + words[i-7] + s1;
        }

        auto a = m_message_digest[0],
             b = m_message_digest[1],
             c = m_message_digest[2],
             d = m_message_digest[3],
             e = m_message_digest[4],
             f = m_message_digest[5],
             g = m_message_digest[6],
             h = m_message_digest[7];

        for(auto i = 0u; i < 64u; ++i)
        {
            const auto S1 = rightrotate<6>(e) xor rightrotate<11>(e) xor rightrotate<25>(e);
            const auto ch = (e bitand f) xor ((not e) bitand g);
            const auto temp1 = h + S1 + ch + k[i] + words[i];
            const auto S0 = rightrotate<2>(a) xor rightrotate<13>(a) xor rightrotate<22>(a);
            const auto maj = (a bitand b) xor (a bitand c) xor (b bitand c);
            const auto temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        m_message_digest[0] += a;
        m_message_digest[1] += b;
        m_message_digest[2] += c;
        m_message_digest[3] += d;
        m_message_digest[4] += e;
        m_message_digest[5] += f;
        m_message_digest[6] += g;
        m_message_digest[7] += h;
    }

    template<typename Type, typename Integer>
    static constexpr byte narrow(Integer number)
    {
        static_assert(is_integral_v<Integer>);
        static_assert(numeric_limits<Type>::digits < numeric_limits<Integer>::digits);
        return static_cast<Type>(number bitand 0b11111111);
    }

    static void encode(span<byte> output, const uint64_t input) noexcept
    {
    	output[7] = narrow<byte>(input >>  0);
    	output[6] = narrow<byte>(input >>  8);
    	output[5] = narrow<byte>(input >> 16);
    	output[4] = narrow<byte>(input >> 24);
    	output[3] = narrow<byte>(input >> 32);
    	output[2] = narrow<byte>(input >> 40);
    	output[1] = narrow<byte>(input >> 48);
    	output[0] = narrow<byte>(input >> 56);
    }

    static void encode(span<byte> output, const span<uint32_t> input) noexcept
    {
    	for(auto i = 0ull, j = 0ull; j < output.size(); ++i, j += 4ull)
        {
    		output[j+3] = narrow<byte>(input[i]);
    		output[j+2] = narrow<byte>(input[i] >>  8);
    		output[j+1] = narrow<byte>(input[i] >> 16);
    		output[j+0] = narrow<byte>(input[i] >> 24);
    	}
    }

    static constexpr array<uint32_t,64> k =
    {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    array<uint32_t,8> m_message_digest;

    uint64_t m_message_length;

    array<byte,20> m_buffer;
};

} // namespace cryptic
