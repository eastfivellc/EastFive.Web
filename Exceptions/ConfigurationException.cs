using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EastFive.Web
{
    public class ConfigurationException : Exception
    {

        public string ParameterName { get; private set; }

        public Type ParameterType { get; private set; }

        public Type ResultType { get; private set; }

        public ConfigurationException(string parameterName, Type parameterType, string message, Type resultType)
            : base(message)
        {
            this.ParameterName = parameterName;
            this.ParameterType = parameterType;
            this.ResultType = resultType;
        }

        public static TResult OnConfigurationFailure<TResult>(string parameterName, Type parameterType, string message)
        {
            throw new ConfigurationException(parameterName, parameterType, message, typeof(TResult));
        }

        public static TResult OnConfigurationFailureWhy<TResult>(string message)
        {
            throw new ConfigurationException(string.Empty, typeof(string), message, typeof(TResult));
        }
    }
}
