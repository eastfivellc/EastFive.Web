using System;
using System.IO;
using System.Security.Cryptography;

namespace EastFive.Security.Crypto
{
	public static class Aes
	{
        public static TResult GenerateGuidKey<TResult>(
            Func<Guid, // key
                TResult> onSuccess)
        {
            using (var provider = System.Security.Cryptography.Aes.Create())
            {
                provider.KeySize = 128; // other key sizes won't fit in a GUID
                return onSuccess(
                    new Guid(provider.Key)); 
            }
        }

        public static Guid AesEncrypt(this Guid dataToEncrypt, Guid secretAseKey)
        {
            using (var aes = System.Security.Cryptography.Aes.Create())
            {
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                aes.Key = secretAseKey.ToByteArray();

                using (var e = aes.CreateEncryptor())
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, e, CryptoStreamMode.Write))
                    {
                        cs.Write(dataToEncrypt.ToByteArray(), 0, 16);
                    }
                    return new Guid(ms.ToArray());
                }
            }
        }

        public static Guid AesDecrypt(this Guid dataToDecrypt, Guid secretAseKey)
        {
            using (var aes = System.Security.Cryptography.Aes.Create())
            {
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                aes.Key = secretAseKey.ToByteArray();

                using (var d = aes.CreateDecryptor())
                using (var ms = new MemoryStream(dataToDecrypt.ToByteArray()))
                using (var cs = new CryptoStream(ms, d, CryptoStreamMode.Read))
                {
                    var bytes = Guid.Empty.ToByteArray();

                    // using .NET 6 approach recommended here: https://github.com/dotnet/runtime/issues/61398
                    int num = 0;
                    while (num < bytes.Length)
                    {
                        int bytesRead = cs.Read(bytes, num, bytes.Length - num);
                        if (bytesRead == 0)
                            break;
                        num += bytesRead;
                    }
                    return new Guid(bytes);
                }
            }
        }
    }
}
