#include <gtest/gtest.h>
#include <string_view>
#include "cryptic/sha256.hpp"

using namespace std::string_literals;

TEST(CrypticSHA256,base64)
{
    auto test1 = ""s;
    EXPECT_EQ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"s, cryptic::sha256::hexadecimal(test1));
}
