#include <ctime>

#include "../nstd.hpp"
#include "../utest.h"

namespace pattern
{
    namespace creational
    {
        /// Abstract Factory is a creational design pattern
        ///     that lets you produce families of related objects
        ///     without specifying their concrete classes.
        namespace abstract_factory
        {
            struct product
            {
                virtual size_t price() const = 0;
            };

            struct consumable : public product
            {
                size_t price() const override { return 10; }
            };

            struct non_consumable : public product
            {
                size_t price() const override { return 100; }
            };

            struct factory
            {
                virtual product* create_product() = 0;
            };

            struct consumable_factory : public factory
            {
                product* create_product() override { return new consumable(); }
            };

            struct non_consumable_factory : public factory
            {
                product* create_product() override { return new non_consumable(); }
            };

            product* create_product(factory& f)
            {
                return f.create_product();
            }
        }
    }
}

using namespace pattern::creational::abstract_factory;

UTEST(pattern_creational, abstract_factory)
{
    srand(static_cast<unsigned int>(time(nullptr)));
    auto random = rand() % 100;

    // Setup factory
    factory* factory;
    if (random % 2 == 0)
        factory = new consumable_factory();
    else
        factory = new non_consumable_factory();
    defer{ delete factory; };

    // Create product
    auto p1 = create_product(*factory);
    defer{ delete p1; };

    // Check price
    if (random % 2 == 0)
        ASSERT_EQ(p1->price(), 10);
    else
        ASSERT_EQ(p1->price(), 100);
}