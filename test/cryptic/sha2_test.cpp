#include <gtest/gtest.h>
#include <string_view>
#include "cryptic/sha2.hpp"

using namespace std::string_literals;

TEST(CrypticSHA224,base64)
{
    auto test1 = ""s;
    EXPECT_EQ("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"s, cryptic::sha224::hexadecimal(test1));
}

TEST(CrypticSHA256,base64)
{
    auto test1 = ""s;
    EXPECT_EQ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"s, cryptic::sha256::hexadecimal(test1));

    auto test2 = "The quick brown fox jumps over the lazy dog"s;
    EXPECT_EQ("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"s, cryptic::sha256::hexadecimal(test2));

    auto test3 = "The quick brown fox jumps over the lazy cog"s;
    EXPECT_EQ("e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be"s, cryptic::sha256::hexadecimal(test3));

}
