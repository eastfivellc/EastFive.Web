using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

using BlackBarLabs;
using BlackBarLabs.Collections.Generic;

namespace BlackBarLabs.Web
{
    public static class UrnExtensions
    {
        public static ResourceQuery ParseUrnQuery(this Uri urn, Assembly assembly)
        {
            var models = assembly.GetTypes()
                .Where(type => type.ContainsCustomAttribute<ResourceTypeAttribute>())
                .ToArray();
            return urn.ParseUrnQuery(models);
        }

        public static ResourceQuery ParseUrnQuery(this Uri urn, Type [] models)
        {
            var urlModelLookup = models
                .Where(type => type.ContainsCustomAttribute<ResourceTypeAttribute>())
                .Select(type =>
                {
                    var resourceTypeAttr = type.GetCustomAttribute<ResourceTypeAttribute>();
                    return new KeyValuePair<string, Type>(resourceTypeAttr.Urn, type);
                })
                .ToDictionary();

            return new ResourceQuery();
        }
    }
}
