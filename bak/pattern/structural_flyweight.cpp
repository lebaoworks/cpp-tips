#include <map>

#include "../utest.h"

namespace pattern
{
    namespace structural
    {
        /// Flyweight is a structural design pattern
        ///     that lets you fit more objects into the available amount of RAM
        ///     by sharing common parts of state between multiple objects instead of keeping all of the data in each object.
        namespace flyweight
        {
            class flyweight
            {
            public:
                virtual ~flyweight() = default;
                virtual void operation() = 0;
            };

            class concrete_flyweight : public flyweight
            {
            public:
                void operation() override
                {
                    // do something
                }
            };

            class flyweight_factory
            {
            private:
                std::map<int, flyweight*> flyweights;

            public:
                flyweight* get_flyweight(int key)
                {
                    if (flyweights.find(key) == flyweights.end())
                        flyweights[key] = new concrete_flyweight();
                    return flyweights[key];
                }

                ~flyweight_factory()
                {
                    for (auto& flyweight : flyweights)
                        delete flyweight.second;
                }
            };
        }
    }
}

using namespace pattern::structural::flyweight;

UTEST(pattern_structural, flyweight)
{
    flyweight_factory factory;
    flyweight* flyweight1 = factory.get_flyweight(1);
    flyweight* flyweight2 = factory.get_flyweight(2);
    flyweight* flyweight3 = factory.get_flyweight(1);

    EXPECT_EQ(flyweight1, flyweight3);
    EXPECT_NE(flyweight1, flyweight2);
}
