using System;
using System.Web;

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
    }
}
