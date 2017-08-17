using System;
using System.Security.Cryptography;
using System.Text;

namespace DeEnCrypt
{
    public static class AESAlgorithmHandle
    {
        public static string GenerateKey(int keySize)
        {
            Aes aes = new AesCryptoServiceProvider()
            {
                KeySize = keySize
            };
            string key = Convert.ToBase64String(aes.Key);
            aes.Clear();
            return key;
        }

        public static string Encrypt(string key, string plainText, PaddingMode paddingMode)
        {
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.Key = Convert.FromBase64String(key);
                aes.Mode = CipherMode.ECB;
                aes.Padding = paddingMode;

                byte[] bytes = Encoding.UTF8.GetBytes(plainText);
                return Convert.ToBase64String(aes.CreateEncryptor().TransformFinalBlock(bytes, 0, bytes.Length));
            }
        }

        public static string Decrypt(string key, string cipherText, PaddingMode paddingMode)
        {
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.Key = Convert.FromBase64String(key);
                aes.Mode = CipherMode.ECB;
                aes.Padding = paddingMode;

                byte[] bytes = Convert.FromBase64String(cipherText);
                return Encoding.UTF8.GetString(aes.CreateDecryptor().TransformFinalBlock(bytes, 0, bytes.Length));
            }
        }
    }
}
