using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;

using Microsoft.IdentityModel.Tokens;

using BlackBarLabs.Web;
using EastFive.Linq;
using EastFive.Security;
using EastFive.Security.Tokens;
using EastFive.Web.Configuration;
using EastFive.Extensions;

namespace BlackBarLabs.Security.Tokens
{
    public static class JwtTools
    {
        //public static TResult GetSessionId<TResult>(this Claim[] claims,
        //    Func<Guid, TResult> found,
        //    Func<TResult> notFound = default(Func<TResult>),
        //    Func<TResult> invalid = default(Func<TResult>))
        //{
        //    return claims.GetGuidValue(ClaimIds.Session,
        //        found, notFound, invalid);
        //}

        //public static TResult GetAuthId<TResult>(this Claim[] claims,
        //    Func<Guid, TResult> found,
        //    Func<TResult> notFound = default(Func<TResult>),
        //    Func<TResult> invalid = default(Func<TResult>))
        //{
        //    return claims.GetGuidValue(ClaimIds.Authorization,
        //        found, notFound, invalid);
        //}

        public static TResult GetGuidValue<TResult>(this Claim[] claims, string key,
            Func<Guid, TResult> found,
            Func<TResult> notFound = default,
            Func<TResult> invalid = default)
        {
            if (default(Func<TResult>) == notFound)
                notFound = () => { throw new Exception("Session not found in claims"); };
            if (default(Func<TResult>) == invalid)
                invalid = notFound;
            return claims
                .Where(claim => claim.Type.DoesEqual(key))
                .FirstOrDefault(
                    (claim) =>
                    {
                        Guid sessionId;
                        if (Guid.TryParse(claim.Value, out sessionId))
                            return found(sessionId);
                        return invalid();
                    },
                    notFound);
        }

        public static TResult ParseAndValidateToken<TResult>(
            this string jwtEncodedString,
            Func<Claim [], TResult> success,
            Func<string, TResult> invalidToken,
            Func<string, TResult> missingConfigurationSetting,
            Func<string, string, TResult> invalidConfigurationSetting,
            string configNameOfIssuerToValidateAgainst = AppSettings.TokenIssuer,
            string configNameOfRsaKeyToValidateAgainst = AppSettings.TokenKey)
        {
            var result = RSA.FromConfig(configNameOfRsaKeyToValidateAgainst,
                rsaProvider =>
                {
                    return configNameOfIssuerToValidateAgainst.ConfigurationString(
                        (issuer) =>
                        {
                            if (string.IsNullOrEmpty(issuer))
                                return missingConfigurationSetting(configNameOfIssuerToValidateAgainst);

                            var validationParameters = new TokenValidationParameters()
                            {
                                ValidateAudience = false,
                                ValidIssuer = issuer,
                                IssuerSigningKey = new Microsoft.IdentityModel.Tokens.RsaSecurityKey(rsaProvider),
                                RequireExpirationTime = true,
                            };

                            try
                            {
                                var handler = new JwtSecurityTokenHandler();
                                var principal = handler.ValidateToken(jwtEncodedString, validationParameters,
                                    out SecurityToken validatedToken);

                                // TODO: Check if token is still valid at current date / time?
                                var claims = principal.Claims.ToArray();

                                return EastFive.Web.Configuration.Settings.GetDateTime(
                                        EastFive.Web.AppSettings.TokenForceRefreshTime,
                                    (notValidBeforeTime) =>
                                    {
                                        if (validatedToken.ValidFrom < notValidBeforeTime)
                                            return EastFive.Web.Configuration.Settings.GetString(
                                                    EastFive.Web.AppSettings.TokenForceRefreshMessage,
                                                (message) => invalidToken(message),
                                                (why) => invalidToken(why));
                                        return success(claims);
                                    },
                                    (why) => success(claims));
                            }
                            catch (ArgumentException ex)
                            {
                                return invalidToken(ex.Message);
                            }
                            catch (SecurityTokenInvalidIssuerException ex)
                            {
                                return invalidToken(ex.Message);
                            }
                            catch (SecurityTokenExpiredException ex)
                            {
                                return invalidToken(ex.Message);
                            }
                            catch (SecurityTokenException ex)
                            {
                                return invalidToken(ex.Message);
                            }
                        },
                        (why) => missingConfigurationSetting(why));
                },
                missingConfigurationSetting,
                invalidConfigurationSetting);
            return result;
        }

        public static TResult ParseToken<TResult>(
            this string jwtEncodedString,
            Func<JwtSecurityToken, TResult> onSuccess,
            Func<string, TResult> invalidToken)
        {
            try
            {
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadJwtToken(jwtEncodedString);
                
                return onSuccess(jwtToken);
            }
            catch (ArgumentException ex)
            {
                return invalidToken(ex.Message);
            }
            catch (SecurityTokenInvalidIssuerException ex)
            {
                return invalidToken(ex.Message);
            }
            catch (SecurityTokenExpiredException ex)
            {
                return invalidToken(ex.Message);
            }
            catch (SecurityTokenException ex)
            {
                return invalidToken(ex.Message);
            }
        }

        public static TResult CreateToken<TResult>(Uri scope,
            DateTime issued, TimeSpan duration,
            IEnumerable<Claim> claims,
            Func<string, TResult> tokenCreated,
            Func<string, TResult> missingConfigurationSetting,
            Func<string, string, TResult> invalidConfigurationSetting,
            string configNameOfIssuer = EastFive.Security.AppSettings.TokenIssuer,
            string configNameOfRSAKey = EastFive.Security.AppSettings.TokenKey)
        {
            return RSA.FromConfig(configNameOfRSAKey,
                (rsaProvider) =>
                {
                    return configNameOfIssuer.ConfigurationString(
                        issuer =>
                        {
                            if (string.IsNullOrWhiteSpace(issuer))
                                return missingConfigurationSetting(configNameOfIssuer);

                            var jwt = rsaProvider.JwtToken(issuer, scope, claims,
                                issued, duration);
                            return tokenCreated(jwt);
                        },
                        missingConfigurationSetting);
                },
                missingConfigurationSetting,
                invalidConfigurationSetting);
        }

        private static bool DoesEqual(this string strA, string strB, bool ignoreCase = false)
        {
            return String.Compare(strA, strB, ignoreCase) == 0;
        }

        public static TResult FirstOrDefault<T, TResult>(this IEnumerable<T> items,
            Func<T, TResult> found,
            Func<TResult> notFound)
        {
            if (items.Any())
                return found(items.First());
            return notFound();
        }
    }
}

namespace EastFive.Security.Tokens
{
    public static class JwtTools
    {
        public static TResult ParseToken<TResult>(
            this string jwtEncodedString,
            Func<Claim[], TResult> success,
            Func<string, TResult> invalidToken,
            Func<string, TResult> missingConfigurationSetting,
            Func<string, string, TResult> invalidConfigurationSetting,
            string configNameOfIssuerToValidateAgainst = EastFive.Security.AppSettings.TokenIssuer,
            string configNameOfRsaKeyToValidateAgainst = EastFive.Security.AppSettings.TokenKey)
        {
            var result = RSA.FromConfig(configNameOfRsaKeyToValidateAgainst,
                rsaProvider =>
                {
                    return configNameOfIssuerToValidateAgainst.ConfigurationString(
                        issuer =>
                        {
                            if (issuer.IsNullOrEmpty())
                                return missingConfigurationSetting(configNameOfIssuerToValidateAgainst);

                            var validationParameters = new TokenValidationParameters()
                            {
                                ValidateAudience = false,
                                ValidIssuer = issuer,
                                IssuerSigningKey = new Microsoft.IdentityModel.Tokens.RsaSecurityKey(rsaProvider),
                                RequireExpirationTime = true,
                            };

                            try
                            {
                                Microsoft.IdentityModel.Tokens.SecurityToken validatedToken;
                                var handler = new JwtSecurityTokenHandler();
                                var principal = handler.ValidateToken(jwtEncodedString, validationParameters, out validatedToken);

                                // TODO: Check if token is still valid at current date / time?
                                var claims = principal.Claims.ToArray();

                                return EastFive.Web.Configuration.Settings.GetDateTime(
                                        EastFive.Web.AppSettings.TokenForceRefreshTime,
                                    (notValidBeforeTime) =>
                                    {
                                        if (validatedToken.ValidFrom < notValidBeforeTime)
                                            return EastFive.Web.Configuration.Settings.GetString(
                                                    EastFive.Web.AppSettings.TokenForceRefreshMessage,
                                                (message) => invalidToken(message),
                                                (why) => invalidToken(why));
                                        return success(claims);
                                    },
                                    (why) => success(claims));
                            }
                            catch (ArgumentException ex)
                            {
                                return invalidToken(ex.Message);
                            }
                            catch (Microsoft.IdentityModel.Tokens.SecurityTokenInvalidIssuerException ex)
                            {
                                return invalidToken(ex.Message);
                            }
                            catch (Microsoft.IdentityModel.Tokens.SecurityTokenExpiredException ex)
                            {
                                return invalidToken(ex.Message);
                            }
                            catch (Microsoft.IdentityModel.Tokens.SecurityTokenException ex)
                            {
                                return invalidToken(ex.Message);
                            }
                        },
                        missingConfigurationSetting);
                },
                missingConfigurationSetting,
                invalidConfigurationSetting);
            return result;
        }

        public static TResult CreateToken<TResult>(
            this string secretAsRSAXmlBase64,
            string issuer,
            Uri scope,
            DateTime issued, TimeSpan duration,
            IEnumerable<Claim> claims,
            Func<string, TResult> tokenCreated,
            Func<string, TResult> onInvalidSecret)
        {
            return RSA.FromConfig(secretAsRSAXmlBase64,
                (rsaProvider) =>
                {
                    var token = rsaProvider.JwtToken(issuer, scope, claims,
                        issued, duration);
                    return tokenCreated(token);
                },
                onInvalidSecret);
        }

        public static string JwtToken(this System.Security.Cryptography.RSACryptoServiceProvider rsaProvider,
            string issuer, Uri scope,
            IEnumerable<Claim> claims,
            DateTime issued, TimeSpan duration)
        {
            var securityKey = new Microsoft.IdentityModel.Tokens.RsaSecurityKey(rsaProvider);

            var signature = new Microsoft.IdentityModel.Tokens.SigningCredentials(
                securityKey, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.RsaSha256Signature);
            var expires = (issued + duration);
            var token = new JwtSecurityToken(issuer, scope.AbsoluteUri, claims, issued, expires, signature);
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.WriteToken(token);
            return jwt;
        }

    }
}