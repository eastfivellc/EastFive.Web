using System;
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
                result.Add(await current);
            }
            return result;
        }
    }
}
