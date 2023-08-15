using System;
using System.IO;
using System.Security.Cryptography;

namespace EastFive.Security.Crypto
{
	public static class Aes
	{
		public static byte[] AesEncrypt(this byte[] dataToEncrypt, System.Security.Cryptography.Aes provider)
		{
			var encryptor = provider.CreateEncryptor();
            using (var ms = new MemoryStream())
            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            using (var sw = new StreamWriter(cs))
            {
                sw.Write(dataToEncrypt);
                sw.Close();
                return ms.ToArray();
            }
        }

        public static byte[] AesDecrypt(this byte[] dataToDecrypt, System.Security.Cryptography.Aes provider)
        {
            var decryptor = provider.CreateDecryptor();
            using (var ms = new MemoryStream(dataToDecrypt))
            using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
            {
                return ms.ToArray();
            }
        }

        public static Guid AesEncrypt(this Guid dataToEncrypt, System.Security.Cryptography.Aes provider)
        {
            var result = AesEncrypt(dataToEncrypt.ToByteArray(), provider);
            return new Guid(result);
        }

        public static Guid AesDecrypt(this Guid dataToDecrypt, System.Security.Cryptography.Aes provider)
        {
            var result = AesDecrypt(dataToDecrypt.ToByteArray(), provider);
            return new Guid(result);
        }
    }
}
