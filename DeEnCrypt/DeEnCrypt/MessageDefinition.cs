namespace DeEnCrypt
{
    public static class MessageDefinition
    {
        public const string AppicationName = "DeEnCrypt";
        public const string ApplicationAbout =
            "DeEnCrypt \n" +
            "Version 1.0.2 \n" +
            "© 2017 TanTran. All right reserved.\n" +
            "DeEnCrypt is developed for encrypt/decrypt your important data by using some common hash algorithm such as: \n" +
            "  - MD5\n" +
            "  - SHA-1\n" +
            "  - SHA-256\n" +
            "  - SHA-512\n" +
            "  - TRIPLE DES\n" +
            "  - RSA\n" +
            "Besides that, it is also used for convert an image to base64 with resize image(optional)\n" +
            "Hope you enjoy it ☺ !!!";

        public const string ApplicationTips = 
            "1. Double click on any field to select all and auto copy.\n" + 
            "2. Look at message field in the bottom to see the status of one action. \n" +
            "3. CLI: Generate RSA private key in XML file \n" +
            "- Pattern: .\\DeEnCrypt.exe rsa genxmlprivatekey [{keysize=<key-size>} | {filename=<file-name>}] \n" +
            "- Default: keysize=2048 & filename = ConnectionEncryptionKeys.xml";

        // Tab 1
        public const string KeyEmpty = "Key field must not be empty.";
        public const string InputTextEmpty = "Input Text field must not be empty.";
        public const string OutputTextEmpty = "Output Text field must not be empty.";
        public const string EncryptSuccess = "Encrypt Success.";
        public const string EncryptFail = "Encrypt Fail.";
        public const string DecryptSuccess = "Decrypt Success.";
        public const string DecryptFail = "Decrypt Fail.";
        public const string GenerateKeySuccess = "Generate Key Success.";
        public const string GenerateKeyFail = "Generate Key fail.";
        public const string ValidateSuccess = "Validate Data Success.";
        public const string ValidateFail = "Validate Data Fail.";

        public const string MD5Algorithm = "MD5";
        public const string SHA1Algorithm = "SHA-1";
        public const string SHA256Algorithm = "SHA-256";
        public const string SHA384Algorithm = "SHA-384";
        public const string SHA512Algorithm = "SHA-512";
        public const string TripleDESAlgorithm = "3DES";

        //Tab 2
        public const string PublicKeyEmpty = "Public key field must not be empty.";
        public const string PrivateKeyEmpty = "Private key field must not be empty.";
        public const string SignatureEmpty = "Signature field must not be empty.";
        public const string VerifySignatureSuccess = "Verify Signature Success.";
        public const string VerifySignatureFail = "Verify Signature Fail.";
        public const string GenerateSignatureSuccess = "Generate Signature Success.";
        public const string GenerateSignatureFail = "Generate Signature Fail.";

        //RSA
        public const string RSAPaddingMode01 = "Pkcs1Encoding";
        public const string RSAPaddingMode02 = "ISO9796d1Encoding";
        public const string RSAPaddingMode03 = "OaepEncoding";

        public static string[] ListPaddingModeForKeyTypePEM =
        {
            RSAPaddingMode01,
            RSAPaddingMode02,
            RSAPaddingMode03
        };

        public const string RSAPaddingModeXML01 = "Pkcs1";
        public const string RSAPaddingModeXML02 = "OaepSHA1";
        public const string RSAPaddingModeXML03 = "OaepSHA256";
        public const string RSAPaddingModeXML04 = "OaepSHA384";
        public const string RSAPaddingModeXML05 = "OaepSHA512";

        public static string[] ListPaddingModeForKeyTypeXML =
        {
            RSAPaddingModeXML01,
            RSAPaddingModeXML02,
            RSAPaddingModeXML03,
            RSAPaddingModeXML04,
            RSAPaddingModeXML05
        };

        public const string RSAAlgorithmSignature01 = "MD5WITHRSA";
        public const string RSAAlgorithmSignature02 = "SHA1WITHRSA";
        public const string RSAAlgorithmSignature03 = "SHA256WITHRSA";
        public const string RSAAlgorithmSignature04 = "SHA384WITHRSA";
        public const string RSAAlgorithmSignature05 = "SHA512WITHRSA";
        //public const string RSAAlgorithmSignature06 = "PSSWITHRSA";
        //public const string RSAAlgorithmSignature07 = "RIPEMD256WITHRSA";

        public static string[] ListAlgorithmSignature = {
            RSAAlgorithmSignature02,
            RSAAlgorithmSignature01,
            RSAAlgorithmSignature03,
            RSAAlgorithmSignature04,
            RSAAlgorithmSignature05
        };
        
        //Tab 3
        public const string UploadImageSuccess = "Upload Image Success.";
        public const string UploadImageFail = "Upload Image Fail.";
        public const string WidthImageEmpty = "Width field must not be empty.";
        public const string HeightImageEmpty = "Height field must not be empty.";
        public const string WidthImageIsNotNumber = "Data in Width field is not a number.";
        public const string HeightImageIsNotNumber = "Data in Height field is not a number.";
        public const string InvalidNumber = "Please enter a valid number between 1 and 99999.";
        public const string ConvertImageSuccess = "Convert Image to Base64 Success.";
        public const string ConvertImageFail = "Convert Image to Base64 Fail.";
        public const string ResizeImageSuccess = "Resize Image Success.";
        public const string BackOriginalImageSuccess = "Back to original image Success.";

        public const string KeyTypeXML = "XML";
        public const string KeyTypePEM = "PEM";

        public const int ReadyToChange = -1;
        public const int ResizeHeightLock = 1;
        public const int ResizeWidthLock = 2;

        //Tab 4
        public const string StringOrBase64Empty = "String field and Base64 field are empty. One of them must not be empty.";
        public const string ConvertStringToBase64Success = "Convert String to Base64 Success.";
        public const string ConvertBase64ToStringSuccess = "Convert Base64 to String Success.";
        public const int FocusedString = 1;
        public const int FocusedBase64 = 2;

        /*
         * CLI DEFINITIONS
         */
        public const string PrivateKeyFileName = "ConnectionEncryptionKeys.xml";

        public const string RSA = "rsa";
        public const string GenXMLKey = "genxmlprivatekey";
        public const string KeySize = "keysize";
        public const string FileName = "filename";
    }
}