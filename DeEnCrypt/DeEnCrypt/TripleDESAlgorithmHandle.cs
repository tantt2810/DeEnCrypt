using System;
using System.Security.Cryptography;
using System.Text;

namespace DeEnCrypt
{
    public static class TripleDESAlgorithmHandle
    {
        public static string GenerateKey(int keySize)
        {
            TripleDES tripleDes = new TripleDESCryptoServiceProvider
            {
                KeySize = keySize
            };
            string key = Convert.ToBase64String(tripleDes.Key);
            //tripleDes.GenerateKey();
            tripleDes.Clear();
            return key;
        }

        public static string Encrypt(string key, string plainText, PaddingMode paddingMode)
        {
            using (TripleDESCryptoServiceProvider tripleDes = new TripleDESCryptoServiceProvider())
            {
                tripleDes.Key = Convert.FromBase64String(key);
                tripleDes.Mode = CipherMode.ECB;
                tripleDes.Padding = paddingMode;

                byte[] bytes = Encoding.UTF8.GetBytes(plainText);
                
                return Convert.ToBase64String(tripleDes.CreateEncryptor().TransformFinalBlock(bytes, 0, bytes.Length));
            }
        }

        public static string Decrypt(string key, string cipherText, PaddingMode paddingMode)
        {
            using (TripleDESCryptoServiceProvider cipher = new TripleDESCryptoServiceProvider())
            {
                cipher.Key = Convert.FromBase64String(key);
                cipher.Mode = CipherMode.ECB;
                cipher.Padding = paddingMode;

                byte[] bytes = Convert.FromBase64String(cipherText);
                return Encoding.UTF8.GetString(cipher.CreateDecryptor().TransformFinalBlock(bytes, 0, bytes.Length));
            }
        }
    }
}
