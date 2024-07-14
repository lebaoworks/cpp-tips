#include <string>

#include "../utest.h"

namespace pattern
{
    namespace structural
    {
        /// Decorator is a structural design pattern
        ///     that lets you attach new behaviors to objects
        ///     by placing these objects inside special wrapper objects that contain the behaviors.
        namespace decorator
        {
            struct base
            {
                virtual ~base() = default;
                virtual std::string say() = 0;
            };

            struct concrete : base
            {
                std::string say() override { return "say my name"; }
            };

            struct decorator : base
            {
            private:
                base* object;
            public:
                decorator(base* obj) : object(obj) {}

                std::string say() override { return object->say(); }

                std::string sing() { return "sing a song: " + object->say(); }
            };
        }
    }
}

using namespace pattern::structural::decorator;

UTEST(pattern_structural, decorator)
{
    concrete c;
    ASSERT_EQ("say my name", c.say());

    decorator d(&c);
    ASSERT_EQ("say my name", d.say());
    ASSERT_EQ("sing a song: say my name", d.sing());
}
