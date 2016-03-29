using System;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net.Http.Headers;

namespace BlackBarLabs.Web
{
    public static class HeaderExtensions
    {
        public static Guid GetUserIdFromAuthorizationHeader(this AuthenticationHeaderValue header)
        {
            try
            {
                var jwtStringPossibleBearer = header.ToString();
                var securityClientJwtString = jwtStringPossibleBearer.ToLower().StartsWith("bearer ") ?
                    jwtStringPossibleBearer.Substring(7) :
                    jwtStringPossibleBearer;
                var securityClientJwt = new JwtSecurityToken(securityClientJwtString);
                var claimsDict = securityClientJwt.Claims.ToDictionary(claim => claim.Type, claim => claim.Value);
                return Guid.Parse(claimsDict[BlackBarLabs.Security.ClaimIds.Authorization]);
            }
            catch (Exception)
            {
                throw new ArgumentException("Problem getting user id from Authorization header");
            }
        }
    }
}
