using EastFive.Security;
using System;
using System.Linq;
using System.Security.Cryptography;

namespace BlackBarLabs.Security.Tokens
{
    public static class VoucherTools
    {
        public static TResult GenerateToken<TResult>(Guid authId, DateTime validUntilUtc,
            Func<string, TResult> success,
            Func<string, TResult> missingConfigurationSetting,
            Func<string, string, TResult> invalidConfigurationSetting)
        {
            byte[] signatureData;
            var hashedData = ComputeHashData(authId, validUntilUtc, out signatureData);

            var result = RSA.FromConfig(AppSettings.CredentialProviderVoucherKey,
                (trustedVoucherPrivateKey) =>
                {
                    var signature = trustedVoucherPrivateKey.SignHash(hashedData, CryptoConfig.MapNameToOID("SHA256"));

                    var tokenBytes = signatureData.Concat(signature).ToArray();
                    var token = Convert.ToBase64String(tokenBytes);
                    return success(token);
                },
                missingConfigurationSetting,
                invalidConfigurationSetting);
            return result;
        }

        public static TResult ValidateToken<TResult>(string accessToken,
            Func<Guid, TResult> success,
            Func<string, TResult> invalidToken,
            Func<string, TResult> tokenExpired,
            Func<string, TResult> invalidSignature,
            Func<string, TResult> missingConfigurationSetting,
            Func<string, string, TResult> invalidConfigurationSetting)
        {
            #region Parse token

            long validUntilTicks = 0;
            var authId = default(Guid);
            var validUntilUtc = default(DateTime);
            var providedSignature = new byte[] {};
            try
            {
                var tokenBytes = Convert.FromBase64String(accessToken);

                var guidSize = Guid.NewGuid().ToByteArray().Length;
                var dateTimeSize = sizeof(long);

                var authIdData = tokenBytes.Take(guidSize).ToArray();
                var validUntilUtcData = tokenBytes.Skip(guidSize).Take(dateTimeSize).ToArray();
                validUntilTicks = BitConverter.ToInt64(validUntilUtcData, 0);

                authId = new Guid(authIdData);
                validUntilUtc = new DateTime(validUntilTicks, DateTimeKind.Utc);
                providedSignature = tokenBytes.Skip(guidSize + dateTimeSize).ToArray();
            }
            catch (Exception ex)
            {
                invalidToken(ex.Message);
            }
            #endregion

            if (validUntilTicks < DateTime.UtcNow.Ticks)
                return tokenExpired("Token has expired");

            byte[] signatureData;
            var hashedData = ComputeHashData(authId, validUntilUtc, out signatureData);

            var result = RSA.FromConfig(AppSettings.CredentialProviderVoucherKey,
                (trustedVoucher) =>
                {
                    if (!trustedVoucher.VerifyHash(hashedData, CryptoConfig.MapNameToOID("SHA256"), providedSignature))
                        return invalidSignature("Cannot verify hash - authId: " + authId +
                           "   validUntilUtc: " + validUntilUtc +
                           "   hashedData: " + hashedData +
                           "   providedSignature: " + providedSignature);

                    return success(authId);
                },
                missingConfigurationSetting,
                invalidConfigurationSetting);
            return result;
        }

        private static byte[] ComputeHashData(Guid authId, DateTime validUntilUtc, out byte[] signatureData)
        {
            var authIdData = authId.ToByteArray();
            var validUntilUtcData = BitConverter.GetBytes(validUntilUtc.Ticks);
            signatureData = authIdData.Concat(validUntilUtcData).ToArray();

            var hash = new SHA256Managed();

            var hashedData = hash.ComputeHash(signatureData);
            return hashedData;
        }
    }
}
