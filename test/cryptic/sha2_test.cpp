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
}
