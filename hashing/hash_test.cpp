#include "hash.hpp"
#include "../utest.h"

UTEST(hashing, MD5)
{
    {
        hashing::hash<hashing::MD5> hash;
        hash.feed("lebaoworks@gmail", 16);

        // 1 hex digest
        auto hex = hash.hex_digest();
        EXPECT_EQ(hex, "0B737437545077EC6FF2393187441A8D");

        // 2 multiple times
        EXPECT_EQ(hex, hash.hex_digest());

        // 3 feed
        hash.feed(".com", 4);
        EXPECT_EQ(hash.hex_digest(), "05AC2DFB7480D1547E99D1FF60033C01");
    }

    {
        // 4 padding
        hashing::hash<hashing::MD5> hash;
        hash.feed("6eabd16e239f03cf3187237747f78c8f0ea07e456eabd16e23aaaaaaa", 57);
        auto hex = hash.hex_digest();
        EXPECT_EQ(hex, "15424B726B74DFF743E8C7128E137C9F");
    }
}

UTEST(hashing, SHA1)
{
    {
        hashing::hash<hashing::SHA1> hash;
        hash.feed("lebaoworks@gmail", 16);

        // 1 hex digest
        auto hex = hash.hex_digest();
        EXPECT_EQ(hex, "DC20F4CA1A7E2DB511418644EDF69E0B831CE98C");

        // 2 multiple times
        EXPECT_EQ(hex, hash.hex_digest());

        // 3 feed
        hash.feed(".com", 4);
        EXPECT_EQ(hash.hex_digest(), "6EABD16E239F03CF3187237747F78C8F0EA07E45");
    }

    {
        // 4 padding
        hashing::hash<hashing::SHA1> hash;
        hash.feed("6eabd16e239f03cf3187237747f78c8f0ea07e456eabd16e23aaaaaaa", 57);
        auto hex = hash.hex_digest();
        EXPECT_EQ(hex, "D50DB2A34B7513AABC3E63E0EC913C2953096D2E");
    }
}

UTEST(hashing, SHA256)
{
    {
        hashing::hash<hashing::SHA256> hash;
        hash.feed("lebaoworks@gmail", 16);

        // 1 hex digest
        auto hex = hash.hex_digest();
        EXPECT_EQ(hex, "D736285BCBE504A601B7A01ECBC0DAD88E95DB846110CC3A0F50A176B1439720");

        // 2 multiple times
        EXPECT_EQ(hex, hash.hex_digest());

        // 3 feed
        hash.feed(".com", 4);
        EXPECT_EQ(hash.hex_digest(), "7A0E47BC9465926BE31799E54885F33B42550AB40BB222617AAFC71715579AC6");
    }

    {
        // 4 padding
        hashing::hash<hashing::SHA256> hash;
        hash.feed("6eabd16e239f03cf3187237747f78c8f0ea07e456eabd16e23aaaaaaa", 57);
        auto hex = hash.hex_digest();
        EXPECT_EQ(hex, "C48EF574E6D59BD0DEFA5D1002EE0B8A2B42C16982A798FDD73F2A2D5E19FE70");
    }
}

struct hashing_benchmark
{
    std::string data;
    size_t size;
};
UTEST_F_SETUP(hashing_benchmark)
{
    utest_fixture->size = 5000000;
    utest_fixture->data = std::string(utest_fixture->size, 0);
}
UTEST_F_TEARDOWN(hashing_benchmark)
{}

UTEST_F(hashing_benchmark, MD5)
{
    hashing::MD5 hash;
    hash.feed(utest_fixture->data.data(), utest_fixture->size);
    auto digest = hash.finalize();
}
UTEST_F(hashing_benchmark, SHA1)
{
    hashing::SHA1 hash;
    hash.feed(utest_fixture->data.data(), utest_fixture->size);
    auto digest = hash.finalize();
}
UTEST_F(hashing_benchmark, SHA256)
{
    hashing::SHA256 hash;
    hash.feed(utest_fixture->data.data(), utest_fixture->size);
    auto digest = hash.finalize();
}