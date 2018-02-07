using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EastFive.Web
{
    public static class JsonExtensions
    {
        public static IEnumerable<dynamic> AsEnumerableDynamics(this JArray array)
        {
            foreach (var item in array)
                yield return (dynamic)item;
        }
    }
}
