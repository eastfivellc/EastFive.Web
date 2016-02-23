using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BlackBarLabs.Web.Extensions
{
    public static class TaskExtensions
    {
        public static async Task<IEnumerable<T>> WhenAll<T>(this IEnumerable<Task<T>> tasks, int maxParallel)
        {
            var lockObject = new object();
            var taskEnumerator = tasks.GetEnumerator();
            var pullTasks = Enumerable
                .Range(0, maxParallel)
                .Select((i) => PullTasks(taskEnumerator, lockObject));

            return (await Task.WhenAll(pullTasks)).SelectMany(task => task);
        }

        private static async Task<IEnumerable<T>> PullTasks<T>(IEnumerator<Task<T>> taskEnumerator, object lockObject)
        {
            var result = new List<T>();
            while(true)
            {
                Task<T> current;
                lock(lockObject)
                {
                    if (!taskEnumerator.MoveNext())
                        break;
                    current = taskEnumerator.Current;
                }
                var currentResult = await current;
                result.Add(currentResult);
            }
            return result;
        }

        public static async Task WhenAll(this IEnumerable<Task> tasks, int maxParallel)
        {
            var lockObject = new object();
            var taskEnumerator = tasks.GetEnumerator();
            var pullTasks = Enumerable
                .Range(0, maxParallel)
                .Select((i) => PullTasks(taskEnumerator, lockObject));

            await Task.WhenAll(pullTasks);
        }

        private static async Task PullTasks(IEnumerator<Task> taskEnumerator, object lockObject)
        {
            while (true)
            {
                Task current;
                lock (lockObject)
                {
                    if (!taskEnumerator.MoveNext())
                        break;
                    current = taskEnumerator.Current;
                }
                await current;
            }
        }

        public static async Task<IEnumerable<Task<T2>>> WhereParallelAsync<T1, T2>(
            this IEnumerable<T1> items,
            Func<T1, Task<bool>> condition,
            Func<T1, Task<T2>> next)
        {
            var itemTasks = new ConcurrentBag<Task<T2>>();
            var iterationTasks = items.Select(item =>
                PeformWhereCheck(item, condition, next, (resultTask) => itemTasks.Add(resultTask)));
            await Task.WhenAll(iterationTasks);
            return itemTasks;
        }

        private static async Task PeformWhereCheck<T1, T2>(T1 item,
            Func<T1, Task<bool>> condition,
            Func<T1, Task<T2>> next,
            Action<Task<T2>> ifSatisfied)
        {
            if (await condition(item))
                ifSatisfied(next(item));
        }
    }
}
