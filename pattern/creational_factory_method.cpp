#include "../nstd.hpp"
#include "../utest.h"

namespace pattern
{
    namespace creational
    {
        /// Factory Method is a creational design pattern
        ///     that provides an interface for creating objects in a superclass,
        ///     but allows subclasses to alter the type of objects that will be created.
        namespace factory_method
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
        
            product* create_product(bool is_consumable)
            {
                if (is_consumable == true)
                    return new consumable();
                else
                    return new non_consumable();
            }
        }
    }
}

using namespace pattern::creational::factory_method;

UTEST(pattern_creational, factory_method)
{
    auto p1 = create_product(true);
    defer{ delete p1; };
    ASSERT_EQ(p1->price(), 10);


    auto p2 = create_product(false);
    defer{ delete p2; };
    ASSERT_EQ(p2->price(), 100);
}