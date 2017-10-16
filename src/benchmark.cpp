
#include <chrono>
#include <iostream>
#include "cryptic/sha1.hpp"

#include <sys/types.h>
#include <openssl/sha.h>

using namespace std::string_literals;

constexpr auto loops = 5'000'000ul;

const auto test = R"(XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

SHA1 benchmark against openssl crypto

)"s;

void cryptic_test()
{
    auto t1 = std::chrono::high_resolution_clock::now();
    auto sha1 = cryptic::sha1{};
    for(auto i = loops; i; --i)
    {
        sha1.hash(test);
        auto hash = sha1.data();
    }
    auto t2 = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1);

    std::clog << "cryptic:" << std::dec << ms.count() << std::endl;
    std::clog << cryptic::sha1::hexadecimal(test) << std::endl;
}

void crypto_test()
{
    auto t1 = std::chrono::high_resolution_clock::now();
    SHA_CTX ctx;
    unsigned char digest[SHA_DIGEST_LENGTH];
    for(auto i = loops; i; --i)
    {
        SHA1_Init(&ctx);
        SHA1_Update(&ctx, (const unsigned char*)test.c_str(), test.size());
        SHA1_Final(digest, &ctx);
    }
    auto t2 = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1);

    std::clog << "crypto:" << std::dec << ms.count() << std::endl;

    for(auto i = 0u; i < SHA_DIGEST_LENGTH; ++i)
        std::clog << std::setw(2) << std::setfill('0') << std::hex << static_cast<unsigned>(digest[i]);
    std::clog << '\n';
}

int main()
{
    cryptic_test();
    crypto_test();
    cryptic_test();
    crypto_test();
    return 0;
}
