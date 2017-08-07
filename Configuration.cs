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
                //var keyValue = Microsoft.Azure.CloudConfigurationManager.GetSetting(key, false, true);
                var keyValue = System.Configuration.ConfigurationManager.AppSettings[key];
                return onFound(keyValue);
            } catch(Exception ex)
            {
                return onUnspecified($"The configuration value for [{key}] is not specified. Please specify a string value");
            }
        }

        public static TResult GetGuid<TResult>(string key,
            Func<Guid, TResult> onParsed,
            Func<string, TResult> unspecifiedOrInvalid)
        {
            return GetString(key,
                (keyValue) =>
                {
                    Guid guidValue;
                    if (!Guid.TryParse(keyValue, out guidValue))
                        return unspecifiedOrInvalid(
                            $"The configuration value for [{key}] is not in the correct format. Please specify a Guid value");
                    return onParsed(guidValue);
                },
                unspecifiedOrInvalid);
        }

        public static TResult GetBase64Bytes<TResult>(string key,
            Func<byte [], TResult> onParsed,
            Func<string, TResult> unspecifiedOrInvalid)
        {
            return GetString(key,
                keyValue =>
                {
                    try
                    {
                        var bytes = Convert.FromBase64String(keyValue);
                        return onParsed(bytes);
                    }
                    catch (Exception ex)
                    {
                        return unspecifiedOrInvalid($"Invalid base64 configuration value for [{key}]: {ex.Message}");
                    }
                },
                (whyString) => unspecifiedOrInvalid($"The configuration value for [{key}] is not specified. Please specify a Base64 value"));
        }
    }
}
