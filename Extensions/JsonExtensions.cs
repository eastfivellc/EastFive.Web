using EastFive.Collections.Generic;
using EastFive.Extensions;
using EastFive.Linq;
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

        public static IEnumerable<IDictionary<string, object>> AsEnumerableDictionary(this JArray array)
        {
            foreach (var item in array)
                yield return item.AsDictionary();
        }

        public static IDictionary<string, object> AsDictionary(this JToken item)
        {
            return item.Aggregate(
                (IDictionary<string, object>)new Dictionary<string, object>(),
                (valuesDictionary, token) =>
                {
                    var valueMaybe = token.AsKeyValuePair();
                    if (!valueMaybe.HasValue)
                        return valuesDictionary;
                    var value = valueMaybe.Value;
                    if (valuesDictionary.ContainsKey(value.Key))
                        return valuesDictionary;
                    return valuesDictionary.Append(value).ToDictionary();
                });
        }

        public static KeyValuePair<string, object>? AsKeyValuePair(this JToken token)
        {
            var key = token.Path.Split('.').Last();
            var jvalue = token.Values<object>().First();
            if (!(jvalue is Newtonsoft.Json.Linq.JValue))
                return default(KeyValuePair<string, object>?);
            var jValueValue = (jvalue as Newtonsoft.Json.Linq.JValue).Value;
            return key.PairWithValue(jValueValue);
        }
    }
}
