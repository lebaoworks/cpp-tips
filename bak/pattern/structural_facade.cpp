#include "../utest.h"

namespace pattern
{
    namespace structural
    {
        /// Facade is a structural design pattern
        ///     that provides a simplified interface to a library, a framework, or any other complex set of classes.
        namespace facade
        {
            struct mp4
            {
            private:
                std::string _path;
            public:
                mp4(std::string& path) : _path(path) {}

                void play() {}
                void stop() {}
            };

            struct mov
            {
            private:
                std::string _path;
            public:
                mov(std::string& path) : _path(path) {}

                void play() {}
                void stop() {}
            };

            struct video_player
            {
            public:
                void play(std::string& path)
                {
                    if (path.find(".mp4") != std::string::npos)
                        mp4(path).play();
                    else if (path.find(".mov") != std::string::npos)
                        mov(path).play();
                }
            };
        }
    }
}

using namespace pattern::structural::facade;

UTEST(pattern_structural, facade)
{
    video_player player;
    std::string path = "video.mp4";
    player.play(path);
}
