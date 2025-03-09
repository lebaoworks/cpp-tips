#include <list>

#include "../utest.h"

namespace pattern
{
    namespace behavior
    {
        /// Chain of Responsibility is a behavioral design pattern
        ///     that lets you pass requests along a chain of handlers.
        /// Upon receiving a request,
        ///     each handler decides either to process the request
        ///     or to pass it to the next handler in the chain.
        namespace chain_of_responsibility
        {
            struct handler
            {
                handler* next = nullptr;

                virtual bool handle(int request) = 0;

                bool pass(int request) { return next != nullptr ? next->handle(request) : false; }

                void set_next(handler* next) { this->next = next; }
            };

            struct handler1 : handler
            {
                bool handle(int request) override
                {
                    if (request == 1)
                        return true;
                    else
                        return pass(request);
                }
            };

            struct handler2 : handler
            {
                bool handle(int request) override
                {
                    if (request == 2)
                        return true;
                    else
                        return pass(request);
                }
            };
        }
    }
}

using namespace pattern::behavior::chain_of_responsibility;

UTEST(pattern_behavior, chain_of_responsibility)
{
    handler1 h1;
    handler2 h2;

    h1.set_next(&h2);

    ASSERT_TRUE(h1.handle(1));
    ASSERT_TRUE(h1.handle(2));
    ASSERT_FALSE(h1.handle(3));
}
