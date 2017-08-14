using System.Security.Cryptography;
using System.Text;

namespace DeEnCrypt
{
    public static class SHAAlgorithmHandle
    {
        public enum SHAAlgorithmType {
            SHA1 = 1, SHA256, SHA384, SHA512
        };
        public static string GetSHAHashData(string data, SHAAlgorithmType SHAType)
        {
            byte[] hashData = new byte[] { };
            switch (SHAType)
            {
                case SHAAlgorithmType.SHA1:
                {
                    SHA1 sha = SHA1.Create();
                    hashData = sha.ComputeHash(Encoding.Default.GetBytes(data));
                    break;
                }
                case SHAAlgorithmType.SHA256:
                {
                    SHA256 sha = SHA256.Create();
                    hashData = sha.ComputeHash(Encoding.Default.GetBytes(data));
                    break;
                }
                case SHAAlgorithmType.SHA384:
                {
                    SHA384 sha = SHA384.Create();
                    hashData = sha.ComputeHash(Encoding.Default.GetBytes(data));
                    break;
                }
                case SHAAlgorithmType.SHA512:
                {
                    SHA512 sha = SHA512.Create();
                    hashData = sha.ComputeHash(Encoding.Default.GetBytes(data));
                    break;
                }
                default:
                {
                    SHA1 sha = SHA1.Create();
                    hashData = sha.ComputeHash(Encoding.Default.GetBytes(data));
                    break;
                }
            }
            //create new instance of StringBuilder to save hashed data
            StringBuilder returnValue = new StringBuilder();

            //loop for each byte and add it to StringBuilder
            foreach(byte x in hashData)
            {
                returnValue.Append(string.Format("{0:X2}", x));
            }

            // return hexadecimal string
            return returnValue.ToString();
        }

        public static bool ValidateSHAHashData(string inputData, string storedHashData, SHAAlgorithmType SHAType)
        {
            //hash input text and save it string variable
            string getHashInputData = GetSHAHashData(inputData, SHAType);

            if (string.Compare(getHashInputData, storedHashData) == 0)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}