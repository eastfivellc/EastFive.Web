using System;
using System.Web;
using System.Linq;

namespace BlackBarLabs.Web
{
    public static class UriExtensions
    {
        public static Uri AddQueryParameter(this Uri uri, string parameter, string value)
        {
            var uriBuilder = new UriBuilder(uri);
            var query = HttpUtility.ParseQueryString(uriBuilder.Query);
            query[parameter] = value;
            uriBuilder.Query = query.ToString();
            return uriBuilder.Uri;
        }

        public static int GetNextParameterIndex(this Uri uri, string parameter)
        {
            var linkUriBuilder = new UriBuilder(uri);
            var linkQuery = HttpUtility.ParseQueryString(linkUriBuilder.Query);
            var parameters = linkQuery.AllKeys.Where(key => key.ToLower().Contains(parameter + "[")).ToList();
            var index = 0;
            if (parameters.Any())
                index = parameters.Select(param => Convert.ToInt32(param.Substring(parameter.Length + 1, 1))).Max() + 1;
            return index;
        }

        public static Uri ReplaceQueryParameterValue(this Uri uri, string parameterName, string newValue)
        {
            var uriBuilder = new UriBuilder(uri);
            var query = HttpUtility.ParseQueryString(uriBuilder.Query);
            query.Set(parameterName, newValue);
            uriBuilder.Query = query.ToString();
            return uriBuilder.Uri;
        }
    }
}
