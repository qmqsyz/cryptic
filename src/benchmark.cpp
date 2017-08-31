
#include <chrono>
#include <iostream>
#include "cryptic/sha1.hpp"

#include <sys/types.h>
#include <openssl/sha.h>

using namespace std::string_literals;

constexpr auto loops = 10'000'000ul;

const auto test = R"(XXXXXXXXXX         XXXXXXXXXXXXXXXXXXXXXXXXXXXX        XXXXXXXXXXXXXXXXXFFFFF

XXXXXXXXXXXXXXXXXFFFFF                           gasdfasdgasdgasgasgasdgasdgasdgasdga

         FFFFFFFFFFFFFFFFFFF     FFFFFFFFFFFFFFFFFFFFFFFFFFFFF
         FFFFFFFFFFFFFFFFFFF     FFFFFFFFFFFFFFFFFFFFFFFFFFFFF
         FFFFFFFFFFFFFFFFFFF     FFFFFFFFFFFFFFFFFFFFFFFFFFFFF
         FFFFFFFFFFFFFFFFFFF     FFFFFFFFFFFFFFFFFFFFFFFFFFFFF
         FFFFFFFFFFFFFFFFFFF     FFFFFFFFFFFFFFFFFFFFFFFFFFFFF
         FFFFFFFFFFFFFFFFFFF     FFFFFFFFFFFFFFFFFFFFFFFFFFFFF
         FFFFFFFFFFFFFFFFFFF     FFFFFFFFFFFFFFFFFFFFFFFFFFFFF
         FFFFFFFFFFFFFFFFFFF     FFFFFFFFFFFFFFFFFFFFFFFFFFFFF
         FFFFFFFFFFFFFFFFFFF     FFFFFFFFFFFFFFFFFFFFFFFFFFFFF
     )"s;

void cryptic_test()
{
    auto t1 = std::chrono::high_resolution_clock::now();
    for(auto i = loops; i; --i)
    {
        // auto hash = cryptic::sha1{test};
        cryptic::sha1{test};
    }
    auto t2 = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1);
    std::clog << "cryptic:" << ms.count() << std::endl;
    std::clog << cryptic::sha1::base64(test) << std::endl;
}

void crypto_test()
{
    auto t1 = std::chrono::high_resolution_clock::now();
    for(auto i = loops; i; --i)
    {
        // auto hash = SHA1((const unsigned char*)test.c_str(), test.size(), nullptr);
        SHA1((const unsigned char*)test.c_str(), test.size(), nullptr);
    }
    auto t2 = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1);
    std::clog << "crypto:" << ms.count() << std::endl;
    auto hash = SHA1((const unsigned char*)test.c_str(), test.size(), nullptr);
    auto x = gsl::make_span(hash, 20);
    std::clog << cryptic::base64::encode(x) << std::endl;
}

int main()
{
    cryptic_test();
    crypto_test();
    cryptic_test();
    crypto_test();
    return 0;
}
