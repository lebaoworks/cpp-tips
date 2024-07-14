#include "../utest.h"

namespace pattern
{
    namespace behavior
    {
        /// Command is a behavioral design pattern
        ///     that turns a request into a stand-alone object
        ///     that contains all information about the request.
        /// This transformation lets you pass requests
        ///     as a method arguments, delay or queue a request’s execution, and support undoable operations.
        namespace command
        {
            struct command
            {
                virtual ~command() = default;
                virtual void execute() = 0;
            };

            struct receiver
            {
                void start() { }
                void stop() { }
            };

            struct start_command : command
            {
                receiver* r;
                start_command(receiver* r) : r(r) { }
                void execute() override { r->start(); }
            };

            struct stop_command : command
            {
                receiver* r;
                stop_command(receiver* r) : r(r) { }
                void execute() override { r->stop(); }
            };
        }
    }
}

using namespace pattern::behavior::command;

UTEST(pattern_behavior, command)
{
    receiver r;
    start_command start(&r);
    stop_command stop(&r);

    start.execute();
    stop.execute();
}
