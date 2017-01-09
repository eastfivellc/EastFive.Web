using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using BlackBarLabs.Security.Tokens;

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

        public static TResult GetAccountIdFromAuthorizationHeader<TResult>(this AuthenticationHeaderValue header,
            Func<Guid, TResult> success,
            Func<TResult> authorizationClaimDoesNotExists)
        {
            try
            {
                var result = header.GetClaimsFromAuthorizationHeader(
                    (claims) =>
                    {
                        var claimsDict = claims.ToDictionary(claim => claim.Type, claim => claim.Value);
                        var authId = Guid.Parse(claimsDict[BlackBarLabs.Security.ClaimIds.Authorization]);
                        return success(authId);
                    },
                    () => authorizationClaimDoesNotExists(),
                    (why) => authorizationClaimDoesNotExists());
                return result;
            }
            catch (Exception)
            {
                throw new ArgumentException("Problem getting user id from Authorization header");
            }
        }

        private const string BearerTokenPrefix = "bearer ";

        public static TResult GetClaimsJwtString<TResult>(this string jwtString,
            Func<IEnumerable<Claim>, TResult> success,
            Func<string, TResult> failure,
            string issuerConfigSetting = "BlackBarLabs.Web.token-issuer",
            string validationKeyConfigSetting = "BlackBarLabs.Web.token-issuer-key")
        {
            try
            {
                var jwtStringPossibleBearer = jwtString;
                var securityClientJwtString = jwtStringPossibleBearer.ToLower().StartsWith(BearerTokenPrefix) ?
                    jwtStringPossibleBearer.Substring(BearerTokenPrefix.Length) :
                    jwtStringPossibleBearer;
                var result = securityClientJwtString.ParseToken(
                    (claims) =>
                    {
                        return success(claims);
                    },
                    (why) =>
                    {
                        return failure(why);
                    },
                    (setting) =>
                    {
                        return failure($"Missing config setting [{setting}]");
                    },
                    (setting, why) =>
                    {
                        return failure($"Invalid config setting[{setting}]:{why}");
                    },
                    issuerConfigSetting, validationKeyConfigSetting);
                return result;
            }
            catch (Exception)
            {
                //throw new ArgumentException("Problem getting user id from Authorization header");
                throw;
            }
        }

        public static TResult GetClaimsFromAuthorizationHeader<TResult>(this AuthenticationHeaderValue header,
            Func<IEnumerable<Claim>, TResult> success,
            Func<TResult> authorizationNotSet,
            Func<string, TResult> failure,
            string issuerConfigSetting = "BlackBarLabs.Web.token-issuer",
            string validationKeyConfigSetting = "BlackBarLabs.Web.token-issuer-key")
        {
            if (default(AuthenticationHeaderValue) == header)
                return authorizationNotSet();
            var jwtString = header.ToString();
            if (String.IsNullOrWhiteSpace(jwtString))
                return authorizationNotSet();
            return jwtString.GetClaimsJwtString(success, failure);
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

        public static IEnumerable<HttpMethod> GetOptions(this HttpContentHeaders headers)
        {
            var optionStrings = headers.Allow;
            return optionStrings
                .Where(option => option.ParseHttpMethod((o) => true, () => false))
                .Select(option => option.ParseHttpMethod(
                    (o) => o, // return parse
                    () => HttpMethod.Get)); // never happens because of Where clause

        }

        public static IEnumerable<HttpMethod> GetOptions(this HttpResponseMessage response)
        {
            return response.Content.Headers.GetOptions();
        }
    }
}
