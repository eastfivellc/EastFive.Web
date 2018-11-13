using System;
using System.Linq;
using System.Security.Claims;

namespace BlackBarLabs.Security
{
    public static class ClaimIds
    {
        public const string Session = "session";
        public const string Authorization = "authorization";
        public const string Role = "role";

        public static ClaimsIdentity GenerateClaimsIdentity(Guid sessionId, Guid authorizationId)
        {
            var userClaims = new ClaimsIdentity();
            userClaims.AddClaim(new Claim(Session, sessionId.ToString()));
            userClaims.AddClaim(new Claim(Authorization, authorizationId.ToString()));
            return userClaims;
        }
        public static ClaimsIdentity GenerateClaimsIdentity(Guid sessionId, Guid authorizationId, int role)
        {
            var userClaims = new ClaimsIdentity();
            userClaims.AddClaim(new Claim(Session, sessionId.ToString()));
            userClaims.AddClaim(new Claim(Authorization, authorizationId.ToString()));
            userClaims.AddClaim(new Claim(Role, role.ToString()));
            return userClaims;
        }


        public static bool TryGetAuthorization(this System.Security.Principal.IIdentity identity,
            out Guid sessionId, out Guid authorizationId)
        {
            sessionId = Guid.Empty;
            authorizationId = Guid.Empty;

            var claimsIdentity = identity as ClaimsIdentity;
            if (claimsIdentity == null)
                return false;

            var claims = claimsIdentity.Claims.ToList();

            var authorizationClaim = claims.FirstOrDefault(x => x.Type == ClaimIds.Authorization);
            if (default(Claim) == authorizationClaim)
                return false;
            var sessionClaim = claims.FirstOrDefault(x => x.Type == ClaimIds.Session);
            if (default(Claim) == sessionClaim)
                return false;

            authorizationId = Guid.Parse(authorizationClaim.Value);
            sessionId = Guid.Parse(sessionClaim.Value);

            return !(sessionId == Guid.Empty || authorizationId == Guid.Empty);
        }

    }
}
