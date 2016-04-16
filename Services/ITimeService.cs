using System;
using System.Security.Claims;

namespace BlackBarLabs.Web.Services
{
    public interface ITimeService
    {
        DateTime Utc { get; }
    }
}