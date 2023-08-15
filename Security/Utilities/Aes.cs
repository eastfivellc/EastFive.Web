using System;
using System.Security.Cryptography;

namespace EastFive.Security
{
	public static class Aes
	{
        public static TResult Generate<TResult>(
            Func<string, // key
                string,  // initialization vector (IV)
                TResult> onSuccess,
                int keySize = 128)
        {
            using (var provider = System.Security.Cryptography.Aes.Create())
            {
                if (provider.KeySize != keySize)
                    provider.KeySize = keySize;

                return onSuccess(
                    Convert.ToBase64String(provider.Key),
                    Convert.ToBase64String(provider.IV));
            }
        }

        public static TResult FromBase64Strings<TResult>(string secretAseKeyBase64, string secretAseInitializationVectorBase64,
            Func<System.Security.Cryptography.Aes, TResult> onSuccess,
            Func<string, TResult> invalidToken)
        {
            var provider = System.Security.Cryptography.Aes.Create();
            try
            {
                provider.Key = Convert.FromBase64String(secretAseKeyBase64);
                provider.IV = Convert.FromBase64String(secretAseInitializationVectorBase64);
                return onSuccess(provider);
            }
            catch (CryptographicException ex)
            {
                return invalidToken(ex.Message);
            }
        }
    }
}

