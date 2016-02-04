using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BlackBarLabs.Web
{
    public class ResourceNotFoundException : Exception
    {
        public ResourceNotFoundException() : base()
        {
        }

        public ResourceNotFoundException(string message) : base(message)
        {
        }
    }

    public class UnauthorizedException : Exception
    {
        public UnauthorizedException() : base()
        {
        }

        public UnauthorizedException(string message) : base(message)
        {
        }
    }
}
