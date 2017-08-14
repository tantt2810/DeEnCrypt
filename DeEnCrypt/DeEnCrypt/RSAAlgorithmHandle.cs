using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace DeEnCrypt
{
    public static class RSAAlgorithmHandle
    {
        /*
         *  Function: GenerateKey()
         *  Key Type: PEM
         *  Description: Generate pair key(private + public)
         */
        public static bool GenerateKey(int keySize, out string publicKey, out string privateKey)
        {
            publicKey = string.Empty;
            privateKey = string.Empty;
            try
            {
                RsaKeyPairGenerator rsa = new RsaKeyPairGenerator();
                rsa.Init(new KeyGenerationParameters(new SecureRandom(), keySize));
                AsymmetricCipherKeyPair key = rsa.GenerateKeyPair();

                //AsymmetricKeyParameter privKey = key.Private;
                //AsymmetricKeyParameter pubKey = key.Public;

                TextWriter textWriter = new StringWriter();
                PemWriter pemWriter = new PemWriter(textWriter);
                pemWriter.WriteObject(key.Private);
                pemWriter.Writer.Flush();

                privateKey = textWriter.ToString();

                textWriter = new StringWriter();
                pemWriter = new PemWriter(textWriter);
                pemWriter.WriteObject(key.Public);
                pemWriter.Writer.Flush();

                publicKey = textWriter.ToString();

                return true;
            }
            catch (Exception e)
            {
                return false;
            }
        }

        /*
         *  Function: ReadPublicKey()
         *  Key Type: PEM
         *  Description: Read public key
         */
        public static AsymmetricKeyParameter ReadPublicKey(string publicKey)
        {
            return (AsymmetricKeyParameter)new PemReader(new StringReader(publicKey)).ReadObject();
        }

        /*
         *  Function: ReadPrivateKey()
         *  Key Type: PEM
         *  Description: Read private key
         */
        public static AsymmetricKeyParameter ReadPrivateKey(string privateKey)
        {
            AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)new PemReader(new StringReader(privateKey)).ReadObject();
            return keyPair.Private;
        }

        /*
         *  Function: EncryptByPublicKey()
         *  Key Type: PEM
         *  Description: Encrypt data by public key, corresponding to function DecryptByPrivateKey()
         */
        public static string EncryptByPublicKey(string plainText, string publicKey, string paddingMode)
        {
            byte[] plainByte = Encoding.UTF8.GetBytes(plainText);
            IAsymmetricBlockCipher encoding;
            switch (paddingMode)
            {
                case MessageDefinition.RSAPaddingMode01:
                    encoding = new Pkcs1Encoding(new RsaEngine());
                    break;
                case MessageDefinition.RSAPaddingMode02:
                    encoding = new ISO9796d1Encoding(new RsaEngine());
                    break;
                default:
                    encoding = new OaepEncoding(new RsaEngine());
                    break;
            }
            encoding.Init(true, ReadPublicKey(publicKey));

            int blockSize = encoding.GetInputBlockSize();
            List<byte> output = new List<byte>();
            for (int chunkPositon = 0; chunkPositon < plainByte.Length; chunkPositon += blockSize)
            {
                int chunkSize = Math.Min(blockSize, plainByte.Length - chunkPositon);
                output.AddRange(encoding.ProcessBlock(plainByte, chunkPositon, chunkSize));
            }
            return Convert.ToBase64String(output.ToArray());
        }

        /*
         *  Function: DecryptByPrivateKey()
         *  Key Type: PEM
         *  Description: Decrypt data by private key, corresponding to function EncryptByPublicKey()
         */
        public static string DecryptByPrivateKey(string encryptedText, string privateKey, string paddingMode)
        {
            byte[] plainByte = Convert.FromBase64String(encryptedText);
            IAsymmetricBlockCipher encoding;
            switch (paddingMode)
            {
                case MessageDefinition.RSAPaddingMode01:
                    encoding = new Pkcs1Encoding(new RsaEngine());
                    break;
                case MessageDefinition.RSAPaddingMode02:
                    encoding = new ISO9796d1Encoding(new RsaEngine());
                    break;
                default:
                    encoding = new OaepEncoding(new RsaEngine());
                    break;
            }
            encoding.Init(false, ReadPrivateKey(privateKey));
            int blockSize = encoding.GetInputBlockSize();
            List<byte> output = new List<byte>();
            for (int chunkPositon = 0; chunkPositon < plainByte.Length; chunkPositon += blockSize)
            {
                int chunkSize = Math.Min(blockSize, plainByte.Length - chunkPositon);
                output.AddRange(encoding.ProcessBlock(plainByte, chunkPositon, chunkSize));
            }
            return Encoding.UTF8.GetString(output.ToArray());
        }

        /*
         *  Function: GenerateSignature()
         *  Key Type: PEM
         *  Description: Generate signature by using data, private key and hash algorithm
         */
        public static string GenerateSignature(string data, string privateKey, string algorithm)
        {
                byte[] dataByte = Encoding.UTF8.GetBytes(data);
                ISigner signer = SignerUtilities.GetSigner(algorithm);
                signer.Init(true, ReadPrivateKey(privateKey));
                signer.BlockUpdate(dataByte, 0, dataByte.Length);
                byte[] inArray = signer.GenerateSignature();
                return Convert.ToBase64String(inArray);
        }

        /*
         *  Function: VerifySignature()
         *  Key Type: PEM
         *  Description: Veiry signature by using data, signature, public key and hash algorithm
         */
        public static bool VerifySignature(string data, string signature, string publicKey, string algorithm)
        {
                byte[] dataByte = Encoding.UTF8.GetBytes(data);
                ISigner signer = SignerUtilities.GetSigner(algorithm);
                signer.Init(false, ReadPublicKey(publicKey));
                signer.BlockUpdate(dataByte, 0, dataByte.Length);
                return signer.VerifySignature(Convert.FromBase64String(signature));
        }
        
        /*
         *  Function: EncryptByPrivateKey()
         *  Key Type: PEM
         *  Description: Encrypt data by private key, corresponding to function DecryptByPublicKey()
         *  Note: Not be used at current
         */
        public static string EncryptByPrivateKey(string plainText, string privateKey)
        {
            try
            {
                byte[] plainByte = Encoding.UTF8.GetBytes(plainText);
                Pkcs1Encoding pkcs1Encoding = new Pkcs1Encoding(new RsaEngine());
                pkcs1Encoding.Init(true, ReadPrivateKey(privateKey));

                int blockSize = pkcs1Encoding.GetInputBlockSize();
                List<byte> output = new List<byte>();
                for (int chunkPositon = 0; chunkPositon < plainByte.Length; chunkPositon += blockSize)
                {
                    int chunkSize = Math.Min(blockSize, plainByte.Length - chunkPositon);
                    output.AddRange(pkcs1Encoding.ProcessBlock(plainByte, chunkPositon, chunkSize));
                }
                return Convert.ToBase64String(output.ToArray());
            }
            catch (Exception e)
            {}
            return string.Empty;
        }

        /*
         *  Function: EncryptByPrivateKey()
         *  Key Type: PEM
         *  Description: Encrypt data by private key, corresponding to function EncryptByPublicKey()
         *  Note: Not be used at current
         */
        public static string DecryptByPublicKey(string encryptedText, string publicKey)
        {
            try
            {
                byte[] plainByte = Convert.FromBase64String(encryptedText);
                Pkcs1Encoding pkcs1Encoding = new Pkcs1Encoding(new RsaEngine());
                pkcs1Encoding.Init(false, ReadPublicKey(publicKey));

                int blockSize = pkcs1Encoding.GetInputBlockSize();
                List<byte> output = new List<byte>();
                for (int chunkPositon = 0; chunkPositon < plainByte.Length; chunkPositon += blockSize)
                {
                    int chunkSize = Math.Min(blockSize, plainByte.Length - chunkPositon);
                    output.AddRange(pkcs1Encoding.ProcessBlock(plainByte, chunkPositon, chunkSize));
                }
                return Encoding.UTF8.GetString(output.ToArray());
            }
            catch (Exception e)
            {}
            return string.Empty;
        }

        /*
         *  Function: GenerateKeyXML()
         *  Key Type: XML
         *  Description: Generate pair key(private + public)
         */
        public static bool GenerateKeyXML(int keySize, out string publicKey, out string privateKey)
        {
            publicKey = null;
            privateKey = null;
            try
            {
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(keySize);
                privateKey = rsa.ToXmlString(true);
                publicKey = rsa.ToXmlString(false);
                return true;
            }
            catch (Exception e)
            {}
            return false;
        }

        /*
         *  Function: EncryptByXMLKey()
         *  Key Type: XML
         *  Description: Encrypt data by public XML key
         */
        public static string EncryptByXMLKey(string inputText, string publicKey, string paddingMode)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(publicKey);
            byte[] inputData = Encoding.UTF8.GetBytes(inputText);
            RSAEncryptionPadding padding;
            switch (paddingMode)
            {
                case MessageDefinition.RSAPaddingModeXML01:
                    padding = RSAEncryptionPadding.Pkcs1;
                    break;
                case MessageDefinition.RSAPaddingModeXML02:
                    padding = RSAEncryptionPadding.OaepSHA1;
                    break;
                case MessageDefinition.RSAPaddingModeXML03:
                    padding = RSAEncryptionPadding.OaepSHA256;
                    break;
                case MessageDefinition.RSAPaddingModeXML04:
                    padding = RSAEncryptionPadding.OaepSHA384;
                    break;
                case MessageDefinition.RSAPaddingModeXML05:
                    padding = RSAEncryptionPadding.OaepSHA512;
                    break;
                default:
                    padding = RSAEncryptionPadding.Pkcs1;
                    break;
            }
            //byte[] encryptedData = rsa.Encrypt(inputData, false);
            byte[] encryptedData = rsa.Encrypt(inputData, padding);
            return Convert.ToBase64String(encryptedData);
        }

        /*
        *  Function: DecryptByXMLKey()
        *  Key Type: XML
        *  Description: Decrypt data by private XML key
        */
        public static string DecryptByXMLKey(string inputText, string privateKey, string paddingMode)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(privateKey);
            byte[] inputData = Convert.FromBase64String(inputText);
            RSAEncryptionPadding padding;
            switch (paddingMode)
            {
                case MessageDefinition.RSAPaddingModeXML01:
                    padding = RSAEncryptionPadding.Pkcs1;
                    break;
                case MessageDefinition.RSAPaddingModeXML02:
                    padding = RSAEncryptionPadding.OaepSHA1;
                    break;
                case MessageDefinition.RSAPaddingModeXML03:
                    padding = RSAEncryptionPadding.OaepSHA256;
                    break;
                case MessageDefinition.RSAPaddingModeXML04:
                    padding = RSAEncryptionPadding.OaepSHA384;
                    break;
                case MessageDefinition.RSAPaddingModeXML05:
                    padding = RSAEncryptionPadding.OaepSHA512;
                    break;
                default:
                    padding = RSAEncryptionPadding.Pkcs1;
                    break;
            }
            //byte[] decryptedData = rsa.Decrypt(inputData, false);
            byte[] decryptedData = rsa.Decrypt(inputData, padding);
            return Encoding.UTF8.GetString(decryptedData);
        }

        /*
        *  Function: GenerateSignatureByXMLKey()
        *  Key Type: XML
        *  Description: Generate signature
        */
        public static string GenerateSignatureByXMLKey(string inputText, string privateKey, string algorithm)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(privateKey);
            byte[] inputData = Encoding.UTF8.GetBytes(inputText);
            HashAlgorithm hash;
            switch (algorithm)
            {
                case MessageDefinition.RSAAlgorithmSignature01:
                    hash = new MD5CryptoServiceProvider();
                    break;
                case MessageDefinition.RSAAlgorithmSignature02:
                    hash = new SHA1CryptoServiceProvider();
                    break;
                case MessageDefinition.RSAAlgorithmSignature03:
                    hash = new SHA256CryptoServiceProvider();
                    break;
                case MessageDefinition.RSAAlgorithmSignature04:
                    hash = new SHA384CryptoServiceProvider();
                    break;
                case MessageDefinition.RSAAlgorithmSignature05:
                    hash = new SHA512CryptoServiceProvider();
                    break;
                default:
                    hash = new SHA1CryptoServiceProvider();
                    break;
            }
            
            byte[] signData = rsa.SignData(inputData, hash);
            return Convert.ToBase64String(signData);
        }
        
        /*
        *  Function: VerifySignatureByXMLKey()
        *  Key Type: XML
        *  Description: Veriry signature
        */
        public static bool VerifySignatureByXMLKey(string inputText, string signature, string publicKey, string algorithm)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(publicKey);
            byte[] inputData = Encoding.UTF8.GetBytes(inputText);
            byte[] signData = Convert.FromBase64String(signature);
            HashAlgorithm hash;
            switch (algorithm)
            {
                case MessageDefinition.RSAAlgorithmSignature01:
                    hash = new MD5CryptoServiceProvider();
                    break;
                case MessageDefinition.RSAAlgorithmSignature02:
                    hash = new SHA1CryptoServiceProvider();
                    break;
                case MessageDefinition.RSAAlgorithmSignature03:
                    hash = new SHA256CryptoServiceProvider();
                    break;
                case MessageDefinition.RSAAlgorithmSignature04:
                    hash = new SHA384CryptoServiceProvider();
                    break;
                case MessageDefinition.RSAAlgorithmSignature05:
                    hash = new SHA512CryptoServiceProvider();
                    break;
                default:
                    hash = new SHA1CryptoServiceProvider();
                    break;
            }
            bool verifyData = rsa.VerifyData(inputData, hash, signData);
            return verifyData;
        }
    }
}

