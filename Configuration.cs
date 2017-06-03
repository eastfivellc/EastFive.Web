using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EastFive.Web.Configuration
{
    public static class Settings
    {
        public static string Get(string key)
        {
            return Microsoft.Azure.CloudConfigurationManager.GetSetting(key);
        }

        [Obsolete]
        public static Uri GetUri(string key)
        {
            return new Uri(Get(key));
        }

        public static TResult GetUri<TResult>(string key,
            Func<Uri, TResult> onParsed,
            Func<string, TResult> unspecifiedOrInvalid)
        {
            var keyValue = Get(key);
            Uri uriValue;
            if (!Uri.TryCreate(keyValue, UriKind.RelativeOrAbsolute, out uriValue))
                return unspecifiedOrInvalid($"The configuration value for [{key}] is not specified. Please specify a URI value");
            return onParsed(uriValue);
        }

        public static TResult GetDouble<TResult>(string key,
            Func<double, TResult> onParsed,
            Func<string, TResult> unspecifiedOrInvalid)
        {
            var keyValue = Get(key);
            double doubleValue;
            if (!double.TryParse(keyValue, out doubleValue))
                return unspecifiedOrInvalid(
                    $"The configuration value for [{key}] is not specified. Please specify a double value");
            return onParsed(doubleValue);
        }

        public static TResult GetString<TResult>(string key,
            Func<string, TResult> onFound,
            Func<string, TResult> onUnspecified)
        {
            try
            {
                var keyValue = Microsoft.Azure.CloudConfigurationManager.GetSetting(key, false, true);
                return onFound(keyValue);
            } catch(Exception)
            {
                return onUnspecified($"The configuration value for [{key}] is not specified. Please specify a string value");
            }
        }
    }
}
