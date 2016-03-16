using System.Security.Claims;

namespace BlackBarLabs.Web.Services
{
    public interface IIdentityService
    {
        Claim GetClaim(string type);
    }
}