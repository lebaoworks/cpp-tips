#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>

#include "../utest.h"

namespace pattern
{
    namespace creational
    {
        /// Object Pool is a creational design pattern
        ///     that manages a pool of reusable objects
        ///     to minimize the overhead of creating and destroying objects.
        //  Object Pool maintains a collection of initialized objects and
        ///     provides mechanisms for clients to efficiently borrow and return objects from the pool
        namespace object_pool
        {
            class worker
            {
            private:
                bool exit = false;
                std::thread thread;
                std::condition_variable cv;
                std::mutex cv_m;

                std::queue<std::function<void()>> tasks;
                
            public:
                worker()
                {
                    bool started = false;
                    std::mutex m_start;
                    std::condition_variable cv_start;

                    thread = std::thread([&]() {
                        {
                            std::lock_guard<std::mutex> lk(m_start);
                            started = true;
                            cv_start.notify_one();
                        }
                        while (exit != true)
                        {
                            std::unique_lock<std::mutex> lk(cv_m);
                            cv.wait(lk);
                        
                            while (tasks.empty() == false)
                            {
                                auto task = std::move(tasks.front());
                                tasks.pop();
                                task();
                            }
                        }
                    });

                    std::unique_lock<std::mutex> lk(m_start);
                    if (started == false)
                        cv_start.wait(lk);
                }
                ~worker()
                {
                    exit = true;
                    cv.notify_all();
                    thread.join();
                }

                void add_task(std::function<void()>&& task)
                {
                    std::lock_guard<std::mutex> lock(cv_m);
                    this->tasks.emplace(std::move(task));
                    cv.notify_one();
                }
            };

            class pool
            {
            private:
                std::queue<std::unique_ptr<worker>> workers;
                std::mutex mutex;

            public:
                std::unique_ptr<worker> get()
                {
                    std::lock_guard<std::mutex> lock(mutex);
                    if (workers.empty() == true)
                        throw std::runtime_error("No worker available");
                    auto ret = std::move(workers.front());
                    workers.pop();
                    return ret;
                }

                void put(std::unique_ptr<worker>&& worker)
                {
                    std::lock_guard<std::mutex> lock(mutex);
                    workers.emplace(std::move(worker));
                }
            };
        }
    }
}

using namespace pattern::creational::object_pool;

UTEST(pattern_creational, object_pool)
{
    // Make a pool of 5 workers
    pool pool;
    for (int i=0; i<5; i++)
        pool.put(std::make_unique<worker>());

    // Make 10 tasks and assign to workers
    int done = 0;
    std::mutex m_done;
    std::condition_variable cv_done;

    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 10; i++)
    {
        auto object = pool.get();
        object->add_task([&]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            {
                std::lock_guard<std::mutex> lock(m_done);
                done++;
                cv_done.notify_one();
            }
        });
        pool.put(std::move(object));
    }
    
    // Wait for all tasks to be done
    std::unique_lock<std::mutex> lock(m_done);
    if (done != 10)
        cv_done.wait(lock, [&]() { return done == 10; });

    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    ASSERT_TRUE(elapsed.count() < 1000);
}