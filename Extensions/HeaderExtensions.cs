using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using BlackBarLabs.Security.Tokens;
using System.Configuration;
using EastFive.Extensions;

namespace EastFive.Web
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

        private const string BearerTokenPrefix = "bearer ";

        public static TResult GetClaimsJwtString<TResult>(this string jwtString,
            Func<IEnumerable<Claim>, TResult> success,
            Func<string, TResult> failure,
            string issuerConfigSetting = EastFive.Security.AppSettings.TokenIssuer,
            string validationKeyConfigSetting = EastFive.Security.AppSettings.TokenKey)
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

        public static bool IsJson(this HttpContent content)
        {
            if (content.Headers.IsDefaultOrNull())
                return false;

            if (content.Headers.ContentType.IsDefaultOrNull())
                return false;

            return String.Compare("application/json", content.Headers.ContentType.MediaType.ToLower(), true) == 0;
        }

        public static bool IsXml(this HttpContent content)
        {
            if (content.Headers.IsDefaultOrNull())
                return false;

            if (content.Headers.ContentType.IsDefaultOrNull())
                return false;

            var mediaTypeStr = content.Headers.ContentType.MediaType.ToLower();
            if (String.Compare("application/xml", mediaTypeStr, true) == 0)
                return true;

            return mediaTypeStr.Contains("xml");
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
