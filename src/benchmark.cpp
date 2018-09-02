
#include <chrono>
#include <iostream>
#include "cryptic/sha1.hpp"
#include "cryptic/sha2.hpp"

#include <sys/types.h>
#include <openssl/sha.h>

using namespace std::string_literals;

constexpr auto loops = 5'000'000ul;

static auto test_case()
{
return R"(XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

SHA1 benchmark against openssl crypto

YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY

)"s;
}

static auto cryptic_hsa1_test()
{
    const auto test = test_case();
    auto t1 = std::chrono::high_resolution_clock::now();
    auto sha1 = cryptic::sha1{};
    for(auto i = loops; i; --i)
    {
        sha1.hash(test);
        auto hash = sha1.data();
    }
    auto t2 = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1);

    std::clog << cryptic::sha1::hexadecimal(test) << '\n';

    return ms.count();
}

static auto cryptic_hsa256_test()
{
    const auto test = test_case();
    auto t1 = std::chrono::high_resolution_clock::now();
    auto sha256 = cryptic::sha256{};
    for(auto i = loops; i; --i)
    {
        sha256.hash(test);
        auto hash = sha256.data();
    }
    auto t2 = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1);

    std::clog << cryptic::sha256::hexadecimal(test) << '\n';

    return ms.count();
}

static auto crypto_hsa1_test()
{
    const auto test = test_case();
    auto t1 = std::chrono::high_resolution_clock::now();
    SHA_CTX ctx;
    unsigned char digest[SHA_DIGEST_LENGTH];
    for(auto i = loops; i; --i)
    {
        SHA1_Init(&ctx);
        SHA1_Update(&ctx, static_cast<const char*>(test.c_str()), test.size());
        SHA1_Final(digest, &ctx);
    }
    auto t2 = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1);

    for(auto i = 0u; i < SHA_DIGEST_LENGTH; ++i)
        std::clog << std::setw(2) << std::setfill('0') << std::hex << static_cast<unsigned>(digest[i]);
    std::clog << std::dec << '\n';

    return ms.count();
}

static auto crypto_hsa256_test()
{
    const auto test = test_case();
    auto t1 = std::chrono::high_resolution_clock::now();
    SHA256_CTX ctx;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    for(auto i = loops; i; --i)
    {
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, static_cast<const char*>(test.c_str()), test.size());
        SHA256_Final(digest, &ctx);
    }
    auto t2 = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1);

    for(auto i = 0u; i < SHA256_DIGEST_LENGTH; ++i)
        std::clog << std::setw(2) << std::setfill('0') << std::hex << static_cast<unsigned>(digest[i]);
    std::clog << std::dec << '\n';

    return ms.count();
}

int main()
{
    std::clog << "SHA1/256 benchmark against openssl crypto - "
              << "looping " << loops << " times:\n";
    auto const t1 = cryptic_hsa1_test();
    std::clog << "cryptic SHA1: " << t1 << " ms\n";
    auto const t2 = crypto_hsa1_test();
    std::clog << "openssl crypto SHA1: "<< t2 << " ms\n";
    std::clog << "cryptic SHA1 was " << t2/t1 << " times faster\n";
    auto const t3 = cryptic_hsa256_test();
    std::clog << "cryptic SHA256: "<< t3 << " ms\n";
    auto const t4 = crypto_hsa256_test();
    std::clog << "openssl crypto SHA256: " << t4 << " ms\n";
    std::clog << "cryptic SHA256 was " << t4/t3 << " times faster\n";
    return 0;
}
