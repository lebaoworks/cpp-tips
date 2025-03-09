#include <string>

#include "../nstd.hpp"
#include "../utest.h"

namespace pattern
{
    namespace creational
    {
        /// Builder is a creational design pattern
        ///     that lets you construct complex objects step by step.
        /// The pattern allows you to produce different types
        ///     and representations of an object using the same construction code.
        namespace builder
        {
            struct house
            {
                std::string foundation;
                std::string wall;
                std::string roof;
                std::string stair;
                std::string furniture;
            };

            struct builder
            {
                house* being_built;
                builder() : being_built(new house()) {}
                ~builder() { delete this->being_built; }

                house* build()
                {
                    auto new_house = new house();
                    house* result = being_built;
                    being_built = new_house;
                    return result;
                }

                builder& build_foundation(const std::string& foundation)
                {
                    being_built->foundation = foundation;
                    return *this;
                }

                builder& build_wall(const std::string& wall)
                {
                    being_built->wall = wall;
                    return *this;
                }

                builder& build_roof(const std::string& roof)
                {
                    being_built->roof = roof;
                    return *this;
                }

                builder& build_stair(const std::string& stair)
                {
                    being_built->stair = stair;
                    return *this;
                }

                builder& make_furniture(const std::string& furniture)
                {
                    being_built->furniture = furniture;
                    return *this;
                }
            };
        }
    }
}

using namespace pattern::creational::builder;

UTEST(pattern_creational, builder)
{
    auto house = builder()
        .build_foundation("concrete")
        .build_wall("brick")
        .build_roof("tile")
        .build_stair("wood")
        .make_furniture("sofa")
        .build();
    defer{ delete house; };

    EXPECT_EQ(house->foundation, "concrete");
    EXPECT_EQ(house->wall, "brick");
    EXPECT_EQ(house->roof, "tile");
    EXPECT_EQ(house->stair, "wood");
    EXPECT_EQ(house->furniture, "sofa");

}