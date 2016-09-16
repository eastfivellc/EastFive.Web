using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;

namespace BlackBarLabs.Web
{
    public static class HeaderExtensions
    {
        public static TResult GetAccountId<TResult>(this IEnumerable<System.Security.Claims.Claim> claims,
            Func<Guid, TResult> success,
            Func<TResult> authorizationClaimDoesNotExists)
        {
            var adminClaim = claims
                .FirstOrDefault((claim) => String.Compare(claim.Type, BlackBarLabs.Security.ClaimIds.Authorization) == 0);

            if (default(System.Security.Claims.Claim) == adminClaim)
                return authorizationClaimDoesNotExists();

            var accountId = Guid.Parse(adminClaim.Value);
            return success(accountId);
        }

        public static Guid GetAccountIdFromAuthorizationHeader(this AuthenticationHeaderValue header)
        {
            try
            {
                var claims = header.GetClaimsFromAuthorizationHeader();
                var claimsDict = claims.ToDictionary(claim => claim.Type, claim => claim.Value);
                return Guid.Parse(claimsDict[BlackBarLabs.Security.ClaimIds.Authorization]);
            }
            catch (Exception)
            {
                throw new ArgumentException("Problem getting user id from Authorization header");
            }
        }

        public static IEnumerable<Claim> GetClaimsJwtString(this string jwtString)
        {
            try
            {
                var jwtStringPossibleBearer = jwtString;
                var securityClientJwtString = jwtStringPossibleBearer.ToLower().StartsWith("bearer ") ?
                    jwtStringPossibleBearer.Substring(7) :
                    jwtStringPossibleBearer;
                var securityClientJwt = new JwtSecurityToken(securityClientJwtString);
                var claimsDict = securityClientJwt.Claims.ToDictionary(claim => claim.Type, claim => claim.Value);
                return claimsDict.Select(claim => new Claim(claim.Key, claim.Value)).ToList();
            }
            catch (Exception)
            {
                throw new ArgumentException("Problem getting user id from Authorization header");
            }
        }

        public static IEnumerable<Claim> GetClaimsFromAuthorizationHeader(this AuthenticationHeaderValue header)
        {
            if (default(AuthenticationHeaderValue) == header)
                yield break;
            var jwtString = header.ToString();
            if (String.IsNullOrWhiteSpace(jwtString))
                yield break;
            foreach (var claim in jwtString.GetClaimsJwtString())
                yield return claim;
        }

        public static TResult ParseHttpMethod<TResult>(this string methodName,
            Func<HttpMethod, TResult> success,
            Func<TResult> failed)
        {
            if (string.Compare(HttpMethod.Delete.Method, methodName, true) == 0)
                return success(HttpMethod.Delete);
            if (string.Compare(HttpMethod.Get.Method, methodName, true) == 0)
                return success(HttpMethod.Get);
            if (string.Compare(HttpMethod.Head.Method, methodName, true) == 0)
                return success(HttpMethod.Head);
            if (string.Compare(HttpMethod.Options.Method, methodName, true) == 0)
                return success(HttpMethod.Options);
            if (string.Compare(HttpMethod.Post.Method, methodName, true) == 0)
                return success(HttpMethod.Post);
            if (string.Compare(HttpMethod.Put.Method, methodName, true) == 0)
                return success(HttpMethod.Put);
            if (string.Compare(HttpMethod.Trace.Method, methodName, true) == 0)
                return success(HttpMethod.Trace);
            return failed();
        }

        public static IEnumerable<HttpMethod> GetOptions(this HttpResponseHeaders headers)
        {
            IEnumerable<string> optionStrings;
            headers.TryGetValues("Allow", out optionStrings);
            return optionStrings
                .Where(option => option.ParseHttpMethod((o) => true, () => false))
                .Select(option => option.ParseHttpMethod(
                    (o) => o, // return parse
                    () => HttpMethod.Get)); // never happens because of Where clause

        }
    }
}
