#pragma once

#include <atomic>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <future>
#include <type_traits>

namespace nstd
{
    /**
     * @brief A thread pool implementation
     * 
     * @note The pool is destroyed after all tasks are completed.
     */
    class thread_pool
    {
    private:
        bool _teardown = false;
        std::mutex _mutex;
        std::condition_variable _cv;
        std::queue<std::packaged_task<void()>> _tasks;
        std::vector<std::thread> _threads;

        void work()
        {
            while (true)
            {
                std::packaged_task<void()> task;
                {
                    std::unique_lock<std::mutex> lock(_mutex);
                    _cv.wait(lock, [this] { return _teardown || !_tasks.empty(); });
                    if (_teardown && _tasks.empty())
                        return;
                    task = std::move(_tasks.front());
                    _tasks.pop();
                }
                task();
            }
        }
    public:

        /**
         * @brief Construct a new thread pool object
         * 
         * @param count Number of threads in the pool
         * @throw std::system_error if the pool cannot be created
         */
        thread_pool(size_t count)
        {
            try
            {
                for (size_t i = 0; i < count; ++i)
                _threads.emplace_back([this] { work(); });
            }
            catch (...)
            {
                {
                    std::lock_guard<std::mutex> lock(_mutex);
                    _teardown = true;
                }
                _cv.notify_all();
                throw;
            }
        }

        ~thread_pool()
        {
            {
                std::lock_guard<std::mutex> lock(_mutex);
                _teardown = true;
            }
            _cv.notify_all();
            for (auto& thread : _threads)
                thread.join();
        }

        /**
         * @brief Submit a task to the pool
         * 
         * @tparam Func Type of the function
         * @tparam Args Types of the arguments
         * @param f Function to be executed
         * @param args Arguments to be passed to the function
         * @return A future object that holds the result of the function
         */
        template<typename Func, typename... Args>
        inline auto submit(Func&& f, Args&&... args)
            -> std::future<std::invoke_result_t<Func, Args...>>
        {
            using result_type = std::invoke_result_t<Func, Args...>;
            std::packaged_task<result_type()> task(std::bind(std::forward<Func>(f), std::forward<Args>(args)...));
            auto future = task.get_future();
            {
                std::lock_guard<std::mutex> lock(_mutex);
                _tasks.emplace(std::move(task));
            }
            _cv.notify_one();
            return future;
        }
    };
}