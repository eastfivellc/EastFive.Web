using System;

namespace BlackBarLabs.Web
{

    public class ResourceConflictException : ArgumentException
    {
        public ResourceConflictException() : base()
        {

        }

        public ResourceConflictException(string message) : base(message)
        {

        }

        public ResourceConflictException(string message, Exception innerException) : base(message, innerException)
        {

        }

        public ResourceConflictException(string message, string paramName) : base(message, paramName)
        {

        }
    }
    
}
