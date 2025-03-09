#include <gtest/gtest.h>
#include <nstd/hash.hpp>

TEST(nstd_hash, MD5)
{
    {
        nstd::hash<nstd::MD5> hash;
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
        nstd::hash<nstd::MD5> hash;
        hash.feed("6eabd16e239f03cf3187237747f78c8f0ea07e456eabd16e23aaaaaaa", 57);
        auto hex = hash.hex_digest();
        EXPECT_EQ(hex, "15424B726B74DFF743E8C7128E137C9F");
    }
}

TEST(nstd_hash, SHA1)
{
    {
        nstd::hash<nstd::SHA1> hash;
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
        nstd::hash<nstd::SHA1> hash;
        hash.feed("6eabd16e239f03cf3187237747f78c8f0ea07e456eabd16e23aaaaaaa", 57);
        auto hex = hash.hex_digest();
        EXPECT_EQ(hex, "D50DB2A34B7513AABC3E63E0EC913C2953096D2E");
    }
}

TEST(nstd_hash, SHA256)
{
    {
        nstd::hash<nstd::SHA256> hash;
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
        nstd::hash<nstd::SHA256> hash;
        hash.feed("6eabd16e239f03cf3187237747f78c8f0ea07e456eabd16e23aaaaaaa", 57);
        auto hex = hash.hex_digest();
        EXPECT_EQ(hex, "C48EF574E6D59BD0DEFA5D1002EE0B8A2B42C16982A798FDD73F2A2D5E19FE70");
    }
}

struct hash_benchmark : public testing::Test
{
    std::string data;
    size_t size;

    void SetUp() override
    {
        size = 5000000;
        data = std::string(size, 0);
    }
};

TEST_F(hash_benchmark, MD5)
{
    nstd::MD5 hash;
    hash.feed(data.data(), size);
    auto digest = hash.finalize();
}

TEST_F(hash_benchmark, SHA1)
{
    nstd::SHA1 hash;
    hash.feed(data.data(), size);
    auto digest = hash.finalize();
}

TEST_F(hash_benchmark, SHA256)
{
    nstd::SHA256 hash;
    hash.feed(data.data(), size);
    auto digest = hash.finalize();
}