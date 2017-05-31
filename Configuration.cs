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

        public static Uri GetUri(string key)
        {
            return new Uri(Get(key));
        }
    }
}
