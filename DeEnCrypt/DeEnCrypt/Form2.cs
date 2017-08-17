using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace DeEnCrypt
{
    public partial class Form2 : Form
    {
        private Image Image, ResizeImage; //use for Tab3
        private ImageFormat ImageFormat; //use for Tab3
        //private TextBox FocusedTextbox; //use for Tab4
        private int focusedTextBoxFlag = MessageDefinition.FocusedString;
        private readonly string[] OneWayAlgorithm = {
            MessageDefinition.MD5Algorithm, MessageDefinition.SHA1Algorithm,
            MessageDefinition.SHA256Algorithm, MessageDefinition.SHA384Algorithm,
            MessageDefinition.SHA512Algorithm
        };
        private readonly string[] TwoWayAlgorithm = { MessageDefinition.TripleDESAlgorithm, MessageDefinition.AESAlgorithm };
        private int WidthHeightFlag = MessageDefinition.ReadyToChange;
        /*
         * WIN FORM PROCESS
         */
        public Form2()
        {
            InitializeComponent();
            this.Text = MessageDefinition.AppicationName;
            tabControl.TabPages[0].Text = "Others";
            tabControl.TabPages[1].Text = "RSA";
            tabControl.TabPages[2].Text = "ImageToBase64";
            tabControl.TabPages[3].Text = "String-Base64";
            //TAB 1
            TextDoubleClick(txtKey);
            TextDoubleClick(txtSalt);
            TextDoubleClick(txtInputText);
            TextDoubleClick(txtOutputText);
            TextDoubleClick(txtBoxMessage);
            //TAB 2
            TextDoubleClick(txtPrivateKeyRSA);
            TextDoubleClick(txtPublicKeyRSA);
            TextDoubleClick(txtInputTextRSA);
            TextDoubleClick(txtGenSignRSA);
            TextDoubleClick(txtEncryptRSA);
            TextDoubleClick(txtDecryptRSA);
            TextDoubleClick(txtMessageRSA);
            //TAB 3
            TextDoubleClick(txtBase64); 
            TextDoubleClick(txtWidthImage);
            TextDoubleClick(txtHeightImage);
            TextDoubleClick(txtMessageImage);
            //TAB 4
            TextDoubleClick(txtStringConvert);
            TextDoubleClick(txtBase64Convert);
            TextDoubleClick(txtMessageStringBase64Convert);

            #region TAB PAGE 1
            /*********************************************************************
             *                           TAB PAGE 1                              *
             *********************************************************************/

            cbxAlgorithm.SelectedIndex = 0;
            cbxKeySize.Items.AddRange(new string[] { "128", "192" });
            cbxKeySize.SelectedIndex = 1;

            Dictionary<int, string> paddingMode = new Dictionary<int, string>();
            paddingMode.Add(Convert.ToInt32(PaddingMode.PKCS7), "PKCS7");
            paddingMode.Add(Convert.ToInt32(PaddingMode.ANSIX923), "ANSIX923");
            paddingMode.Add(Convert.ToInt32(PaddingMode.ISO10126), "ISO10126");
            paddingMode.Add(Convert.ToInt32(PaddingMode.Zeros), "Zeros");
            paddingMode.Add(Convert.ToInt32(PaddingMode.None), "None");

            cbxPaddingMode.DataSource = new BindingSource(paddingMode, null);
            cbxPaddingMode.DisplayMember = "Value";
            cbxPaddingMode.ValueMember = "Key";
            cbxPaddingMode.SelectedIndex = 0;

            //combobox Algorithm Change Event Handle
            cbxAlgorithm.SelectedIndexChanged += (sender, args) =>
            {
                bool flag = false;
                foreach (string algorithm in TwoWayAlgorithm)
                {
                    if (cbxAlgorithm.SelectedItem.ToString() == algorithm)
                    {
                        flag = true;
                        if (algorithm == MessageDefinition.TripleDESAlgorithm)
                        {
                            cbxKeySize.Items.Clear();
                            cbxKeySize.Items.AddRange(new string[] { "128", "192" });
                            cbxKeySize.SelectedIndex = 1;
                        }
                        if(algorithm == MessageDefinition.AESAlgorithm)
                        {
                            cbxKeySize.Items.Clear();
                            cbxKeySize.Items.AddRange(new string[] { "128", "192", "256" });
                            cbxKeySize.SelectedIndex = 1;
                        }
                        break;
                    }
                }
                cbxKeySize.Enabled = flag;
                txtKey.Enabled = flag;
                btnDecrypt.Enabled = flag;
                btnGenerateKey.Enabled = flag;
                txtSalt.Enabled = !flag;
                cbxPaddingMode.Enabled = flag;
                radEnable.Enabled = !flag;
                radDisable.Enabled = !flag;
                btnValidate.Enabled = !radDisable.Checked && !flag;
                btnEncrypt.Enabled = radDisable.Checked || !radDisable.Enabled;
            };

            //Radio Button Disable change event handle
            radDisable.CheckedChanged += (sender, args) =>
            {
                bool isChecked = radDisable.Checked;
                
                btnEncrypt.Enabled = isChecked;
                btnValidate.Enabled = !isChecked;
                lblOutputText.Text = isChecked ? "Output Text" : "Encrypted Text";
                txtOutputText.ReadOnly = isChecked;
            };

            //Button Validate Click Event Handle
            btnValidate.Click += (sender, args) =>
            {
                //if (radDisable.Enabled == false)
                //    return;
                try
                {
                    string algorithm = cbxAlgorithm.SelectedItem.ToString();
                    string inputData = txtInputText.Text + txtSalt.Text;
                    string encryptedData = txtOutputText.Text;
                    bool rs = false;
                    switch (algorithm)
                    {
                        case MessageDefinition.MD5Algorithm:
                            rs = MD5AlgorithmHandle.ValidateMD5HashData(inputData, encryptedData);
                            break;
                        case MessageDefinition.SHA1Algorithm:
                            rs = SHAAlgorithmHandle.ValidateSHAHashData(inputData, encryptedData,
                                SHAAlgorithmHandle.SHAAlgorithmType.SHA1);
                            break;
                        case MessageDefinition.SHA256Algorithm:
                            rs = SHAAlgorithmHandle.ValidateSHAHashData(inputData, encryptedData,
                                SHAAlgorithmHandle.SHAAlgorithmType.SHA256);
                            break;
                        case MessageDefinition.SHA384Algorithm:
                            rs = SHAAlgorithmHandle.ValidateSHAHashData(inputData, encryptedData,
                                SHAAlgorithmHandle.SHAAlgorithmType.SHA384);
                            break;
                        case MessageDefinition.SHA512Algorithm:
                            rs = SHAAlgorithmHandle.ValidateSHAHashData(inputData, encryptedData,
                                SHAAlgorithmHandle.SHAAlgorithmType.SHA512);
                            break;
                    }
                    if (rs)
                        DisplayMessage(txtBoxMessage, MessageDefinition.ValidateSuccess, Color.Green);
                    else
                        DisplayMessage(txtBoxMessage, MessageDefinition.ValidateFail, Color.Red);
                }
                catch (Exception e)
                {
                    DisplayMessage(txtBoxMessage, e.Message, Color.Red);
                }
                
            };

            //Button Generate Click Event Handle
            btnGenerateKey.Click += (sender, args) =>
            {
                try
                {
                    string algorithmType = cbxAlgorithm.SelectedItem.ToString();
                    string keySize = cbxKeySize.SelectedItem.ToString();
                    string key;
                    if (algorithmType == MessageDefinition.AESAlgorithm)
                        key = AESAlgorithmHandle.GenerateKey(int.Parse(keySize));
                    else //TripleDES
                        key = TripleDESAlgorithmHandle.GenerateKey(int.Parse(keySize));
                    txtKey.Text = key;
                    if (string.IsNullOrEmpty(key))
                        DisplayMessage(txtBoxMessage, MessageDefinition.GenerateKeyFail, Color.Red);
                    else
                        DisplayMessage(txtBoxMessage, MessageDefinition.GenerateKeySuccess, Color.Green);
                }
                catch (Exception exception)
                {
                    DisplayMessage(txtBoxMessage, exception.Message, Color.Red);
                }
            };

            //Button Encrypt Click Event Handle
            btnEncrypt.Click += (sender, args) =>
            {
                try
                {
                    if (CheckValidateBeforeHandle() == false)
                        return;
                    string key = txtKey.Text;
                    string inputText = txtInputText.Text;
                    string outputText;
                    string algorithmType = cbxAlgorithm.SelectedItem.ToString();
                    if (algorithmType == MessageDefinition.MD5Algorithm)
                        outputText = MD5AlgorithmHandle.GetMD5HashData(inputText + txtSalt.Text);
                    else if (algorithmType == MessageDefinition.SHA1Algorithm)
                        outputText = SHAAlgorithmHandle.GetSHAHashData(inputText + txtSalt.Text, SHAAlgorithmHandle.SHAAlgorithmType.SHA1);
                    else if (algorithmType == MessageDefinition.SHA256Algorithm)
                        outputText = SHAAlgorithmHandle.GetSHAHashData(inputText + txtSalt.Text, SHAAlgorithmHandle.SHAAlgorithmType.SHA256);
                    else if (algorithmType == MessageDefinition.SHA384Algorithm)
                        outputText = SHAAlgorithmHandle.GetSHAHashData(inputText + txtSalt.Text, SHAAlgorithmHandle.SHAAlgorithmType.SHA384);
                    else if (algorithmType == MessageDefinition.SHA512Algorithm)
                        outputText =
                            SHAAlgorithmHandle.GetSHAHashData(inputText + txtSalt.Text, SHAAlgorithmHandle.SHAAlgorithmType.SHA512);
                    else if (algorithmType == MessageDefinition.AESAlgorithm)
                    {
                        PaddingMode pMode = (PaddingMode)((KeyValuePair<int, string>)cbxPaddingMode.SelectedItem).Key;
                        outputText = AESAlgorithmHandle.Encrypt(key, inputText, pMode);
                    }
                    else //TripleDES
                    {
                        PaddingMode pMode = (PaddingMode)((KeyValuePair<int, string>)cbxPaddingMode.SelectedItem).Key;
                        outputText = TripleDESAlgorithmHandle.Encrypt(key, inputText, pMode);
                    }

                    txtOutputText.Text = outputText;
                    if (string.IsNullOrEmpty(outputText))
                        DisplayMessage(txtBoxMessage, MessageDefinition.EncryptFail, Color.Red);
                    else
                        DisplayMessage(txtBoxMessage, MessageDefinition.EncryptSuccess, Color.Green);
                }
                catch (Exception e)
                {
                    DisplayMessage(txtBoxMessage, MessageDefinition.EncryptFail + "\n" + e.Message, Color.Red);
                }


            };

            //Button Decrypt Click Event Handle
            btnDecrypt.Click += (sender, args) =>
            {
                try
                {
                    if (CheckValidateTwoWay() == false)
                        return;
                    string key = txtKey.Text;
                    string inputText = txtInputText.Text;
                    PaddingMode pMode = (PaddingMode)((KeyValuePair<int, string>)cbxPaddingMode.SelectedItem).Key;
                    string algorithmType = cbxAlgorithm.SelectedItem.ToString();
                    string outputText;
                    if (algorithmType == MessageDefinition.AESAlgorithm)
                        outputText = AESAlgorithmHandle.Decrypt(key, inputText, pMode);
                    else //TripleDES
                        outputText = TripleDESAlgorithmHandle.Decrypt(key, inputText, pMode);
                    txtOutputText.Text = outputText;
                    if (string.IsNullOrEmpty(outputText))
                        DisplayMessage(txtBoxMessage, MessageDefinition.DecryptFail, Color.Red);
                    else
                        DisplayMessage(txtBoxMessage, MessageDefinition.DecryptSuccess, Color.Green);
                }
                catch (Exception e)
                {
                    DisplayMessage(txtBoxMessage, MessageDefinition.DecryptFail + "\n" + e.Message, Color.Red);
                }

            };

            
            #endregion

            #region TAB PAGE 2 
            /*********************************************************************
             *                           TAB PAGE 2                              *
             *********************************************************************/
            cbxKeySizeRSA.SelectedIndex = 1;
            cbxAlgorithmSignatureRSA.Items.AddRange(MessageDefinition.ListAlgorithmSignature);
            cbxAlgorithmSignatureRSA.SelectedIndex = 0;
            cbxKeyTypeRSA.SelectedIndex = 0;
            cbxPaddingModeRSA.Items.AddRange(MessageDefinition.ListPaddingModeForKeyTypeXML);
            cbxPaddingModeRSA.SelectedIndex = 0;

            //Combobox Key Type On change envent handle
            cbxKeyTypeRSA.SelectedIndexChanged += (sender, args) =>
            {
                string keyType = cbxKeyTypeRSA.SelectedItem.ToString();
                if (keyType == MessageDefinition.KeyTypeXML)
                {
                    cbxPaddingModeRSA.Items.Clear();
                    cbxPaddingModeRSA.Items.AddRange(MessageDefinition.ListPaddingModeForKeyTypeXML);
                    cbxPaddingModeRSA.SelectedIndex = 0;
                }
                else
                {
                    cbxPaddingModeRSA.Items.Clear();
                    cbxPaddingModeRSA.Items.AddRange(MessageDefinition.ListPaddingModeForKeyTypePEM);
                    cbxPaddingModeRSA.SelectedIndex = 0;
                }
            };
            
            //Button Generate Key RSA Handle
            btnGenKeyRSA.Click += (sender, args) =>
            {
                try
                {
                    string publicKey = string.Empty;
                    string privateKey = string.Empty;
                    int keySize = int.Parse(cbxKeySizeRSA.SelectedItem.ToString());
                    string keyType = cbxKeyTypeRSA.SelectedItem.ToString();
                    bool genKey;
                    if (keyType == MessageDefinition.KeyTypeXML)
                        genKey = RSAAlgorithmHandle.GenerateKeyXML(keySize, out publicKey, out privateKey);
                    else
                        genKey = RSAAlgorithmHandle.GenerateKey(keySize, out publicKey, out privateKey);
                    
                    txtPrivateKeyRSA.Text = privateKey;
                    txtPublicKeyRSA.Text = publicKey;
                    if (genKey)
                        DisplayMessage(txtMessageRSA, MessageDefinition.GenerateKeySuccess, Color.Green);
                    else
                        DisplayMessage(txtMessageRSA, MessageDefinition.GenerateKeyFail, Color.Red);
                }
                catch (Exception e)
                {
                    DisplayMessage(txtMessageRSA, e.Message, Color.Red);
                }
            };

            //Button Encrypt RSA Handle
            btnEncryptRSA.Click += (sender, args) =>
            {
                try
                {
                    string inputText = txtInputTextRSA.Text;
                    string publicKey = txtPublicKeyRSA.Text;
                    string padding = cbxPaddingModeRSA.SelectedItem.ToString().Trim();
                    string keyType = cbxKeyTypeRSA.SelectedItem.ToString();
                    string encryptRSA;

                    if (string.IsNullOrEmpty(publicKey))
                    {
                        DisplayMessage(txtMessageRSA, MessageDefinition.PublicKeyEmpty, Color.Red);
                        return;
                    }

                    if (string.IsNullOrEmpty(inputText))
                    {
                        DisplayMessage(txtMessageRSA, MessageDefinition.InputTextEmpty, Color.Red);
                        return;
                    }
                    if (keyType == MessageDefinition.KeyTypeXML)
                        encryptRSA = RSAAlgorithmHandle.EncryptByXMLKey(inputText, publicKey, padding);
                    else
                        encryptRSA = RSAAlgorithmHandle.EncryptByPublicKey(inputText, publicKey, padding);
                    txtEncryptRSA.Text = encryptRSA;
                    if (string.IsNullOrEmpty(encryptRSA))
                        DisplayMessage(txtMessageRSA, MessageDefinition.EncryptFail, Color.Red);
                    else
                        DisplayMessage(txtMessageRSA, MessageDefinition.EncryptSuccess, Color.Green);
                }
                catch (Exception e)
                {
                    DisplayMessage(txtMessageRSA, e.Message, Color.Red);
                }
                
            };

            //Button Decrypt RSA Handle
            btnDecryptRSA.Click += (sender, args) =>
            {
                try
                {
                    string encryptedText = txtInputTextRSA.Text;
                    string privateKey = txtPrivateKeyRSA.Text;
                    string padding = cbxPaddingModeRSA.SelectedItem.ToString().Trim();
                    string keyType = cbxKeyTypeRSA.SelectedItem.ToString();
                    string decryptRSA;
                    if (string.IsNullOrEmpty(privateKey))
                    {
                        DisplayMessage(txtMessageRSA, MessageDefinition.PrivateKeyEmpty, Color.Red);
                        return;
                    }
                    if (string.IsNullOrEmpty(encryptedText))
                    {
                        DisplayMessage(txtMessageRSA, MessageDefinition.InputTextEmpty, Color.Red);
                        return;
                    }
                    if (keyType == MessageDefinition.KeyTypeXML)
                        decryptRSA = RSAAlgorithmHandle.DecryptByXMLKey(encryptedText, privateKey, padding);
                    else
                        decryptRSA = RSAAlgorithmHandle.DecryptByPrivateKey(encryptedText, privateKey, padding);
                    txtDecryptRSA.Text = decryptRSA;
                    if (string.IsNullOrEmpty(decryptRSA))
                        DisplayMessage(txtMessageRSA, MessageDefinition.DecryptFail, Color.Red);
                    else
                        DisplayMessage(txtMessageRSA, MessageDefinition.DecryptSuccess, Color.Green);
                }
                catch (Exception e)
                {
                    DisplayMessage(txtMessageRSA, e.Message, Color.Red);
                }
                
            };

            //Button Generate Signature Handle
            btnGenSignRSA.Click += (sender, args) =>
            {
                try
                {
                    string inputText = txtInputTextRSA.Text;
                    string privateKey = txtPrivateKeyRSA.Text;
                    string algorithm = cbxAlgorithmSignatureRSA.SelectedItem.ToString().Trim();
                    string keyType = cbxKeyTypeRSA.SelectedItem.ToString();
                    string generateSignature;
                    if (string.IsNullOrEmpty(privateKey))
                    {
                        DisplayMessage(txtMessageRSA, MessageDefinition.PrivateKeyEmpty, Color.Red);
                        return;
                    }
                    if (string.IsNullOrEmpty(inputText))
                    {
                        DisplayMessage(txtMessageRSA, MessageDefinition.InputTextEmpty, Color.Red);
                        return;
                    }
                    if (keyType == MessageDefinition.KeyTypeXML)
                    {
                        generateSignature = RSAAlgorithmHandle.GenerateSignatureByXMLKey(inputText, privateKey, algorithm);
                    }
                    else
                        generateSignature = RSAAlgorithmHandle.GenerateSignature(inputText, privateKey, algorithm);

                    txtGenSignRSA.Text = generateSignature;
                    if (string.IsNullOrEmpty(generateSignature))
                        DisplayMessage(txtMessageRSA, MessageDefinition.GenerateSignatureFail, Color.Red);
                    else
                        DisplayMessage(txtMessageRSA, MessageDefinition.GenerateSignatureSuccess, Color.Green);
                }
                catch (Exception e)
                {
                    DisplayMessage(txtMessageRSA, e.Message, Color.Red);
                }
                
            };

            //Button Verify Signature Handle
            btnVeryfySignRSA.Click += (sender, args) =>
            {
                try
                {
                    string inputText = txtInputTextRSA.Text;
                    string publicKey = txtPublicKeyRSA.Text;
                    string signature = txtGenSignRSA.Text;
                    string algorithm = cbxAlgorithmSignatureRSA.SelectedItem.ToString().Trim();
                    string keyType = cbxKeyTypeRSA.SelectedItem.ToString();
                    bool verirySignature;
                    if (string.IsNullOrEmpty(publicKey))
                    {
                        DisplayMessage(txtMessageRSA, MessageDefinition.PublicKeyEmpty, Color.Red);
                        return;
                    }
                    if (string.IsNullOrEmpty(inputText))
                    {
                        DisplayMessage(txtMessageRSA, MessageDefinition.InputTextEmpty, Color.Red);
                        return;
                    }
                    if (string.IsNullOrEmpty(signature))
                    {
                        DisplayMessage(txtMessageRSA, MessageDefinition.SignatureEmpty, Color.Red);
                        return;
                    }
                    if (keyType == MessageDefinition.KeyTypeXML)
                        verirySignature = RSAAlgorithmHandle.VerifySignatureByXMLKey(inputText, signature, publicKey, algorithm);
                    else
                        verirySignature = RSAAlgorithmHandle.VerifySignature(inputText, signature, publicKey, algorithm);
                    if (verirySignature)
                        DisplayMessage(txtMessageRSA, MessageDefinition.VerifySignatureSuccess, Color.Green);
                    else
                        DisplayMessage(txtMessageRSA, MessageDefinition.VerifySignatureFail, Color.Red);
                }
                catch (Exception e)
                {
                    DisplayMessage(txtMessageRSA, e.Message, Color.Red);
                }
               
            };

            #endregion

            #region TAB PAGE 3
            /*********************************************************************
             *                           TAB PAGE 3                              *
             *********************************************************************/
            EnableAfterUploaded(false);
            
            btnUploadFile.Click += (sender, args) =>
            {
                try
                {
                    OpenFileDialog fd = new OpenFileDialog();
                    Image = ImageToBase64.UploadImage(out fd);
                    ResizeImage = Image;
                    ImageFormat = Image.RawFormat;
                    pictureBox.Image = Image;
                    lblFileName.Text = fd.SafeFileName;
                    EnableAfterUploaded(true);
                    txtWidthImage.Text = Image.Width.ToString();
                    txtHeightImage.Text = Image.Height.ToString();
                    if (File.Exists(fd.FileName))
                        DisplayMessage(txtMessageImage, MessageDefinition.UploadImageSuccess, Color.Green);
                    else
                        DisplayMessage(txtMessageImage, MessageDefinition.UploadImageFail, Color.Red);
                }
                catch (Exception e)
                {
                    DisplayMessage(txtMessageImage, e.Message, Color.Red);
                }
            };
            
            //Text Width prevent to type anything accept number
            txtWidthImage.KeyPress += (sender, args) =>
            {
                if (!char.IsControl(args.KeyChar) && !char.IsDigit(args.KeyChar))
                {
                    args.Handled = true;
                }
            };

            //Text Height prevent to type anything accept number
            txtHeightImage.KeyPress += (sender, args) =>
            {
                if (!char.IsControl(args.KeyChar) && !char.IsDigit(args.KeyChar))
                {
                    args.Handled = true;
                }
            };

            //Text Height on change event handle
            txtHeightImage.TextChanged += (sender, args) =>
            {
                if (WidthHeightFlag == MessageDefinition.ResizeWidthLock /*|| WidthHeightFlag == 0*/)
                {
                    WidthHeightFlag = MessageDefinition.ReadyToChange;
                    return;
                }
                    
                try
                {
                    string newHeight = txtHeightImage.Text;
                    if (string.IsNullOrEmpty(newHeight))
                    {
                        return;
                    }
                    int newWidth = ImageToBase64.GetNewWidth(Image, Convert.ToInt32(newHeight));
                    WidthHeightFlag = MessageDefinition.ResizeHeightLock;
                    txtWidthImage.Text = newWidth.ToString();
                }
                catch (Exception ex)
                {
                    DisplayMessage(txtMessageImage, ex.Message, Color.Red);
                }
            };

            //Text Width on change event handle
            txtWidthImage.TextChanged += (sender, args) =>
            {
                if (WidthHeightFlag == MessageDefinition.ResizeHeightLock /*|| WidthHeightFlag == 0*/)
                {
                    WidthHeightFlag = MessageDefinition.ReadyToChange;
                    return;
                }
                    
                try
                {
                    string newWidth = txtWidthImage.Text;
                    if (string.IsNullOrEmpty(newWidth))
                    {
                        return;
                    }
                    int newHeight = ImageToBase64.GetNewHeight(Image, Convert.ToInt32(newWidth));
                    WidthHeightFlag = MessageDefinition.ResizeWidthLock;
                    txtHeightImage.Text = newHeight.ToString();
                }
                catch (Exception e)
                {
                    DisplayMessage(txtMessageImage, e.Message, Color.Red);
                }
            };

            //Button Resize on click event handle
            btnResizeImage.Click += (sender, args) =>
            {
                string width = txtWidthImage.Text;
                string height = txtHeightImage.Text;
                int widthNum;
                int heightNum;
                if (string.IsNullOrEmpty(width))
                {
                    DisplayMessage(txtMessageImage, MessageDefinition.WidthImageEmpty, Color.Red);
                    return;
                }
                if (string.IsNullOrEmpty(height))
                {
                    DisplayMessage(txtMessageImage, MessageDefinition.HeightImageEmpty, Color.Red);
                    return;
                }
                if (int.TryParse(width, out widthNum) == false)
                {
                    DisplayMessage(txtMessageImage, MessageDefinition.WidthImageIsNotNumber, Color.Red);
                    return;
                }
                if (int.TryParse(height, out heightNum) == false)
                {
                    DisplayMessage(txtMessageImage, MessageDefinition.HeightImageIsNotNumber, Color.Red);
                    return;
                }
                if (widthNum <= 0 || heightNum <= 0)
                {
                    DisplayMessage(txtMessageImage, MessageDefinition.InvalidNumber, Color.Red);
                    return;
                }
                try
                {
                    Size size = new Size(widthNum, heightNum);
                    Image newImage = new Bitmap(widthNum, heightNum);
                    using (Graphics GFX = Graphics.FromImage((Bitmap)newImage))
                    {
                        GFX.DrawImage(Image, new Rectangle(Point.Empty, size));
                    }
                    //newImage.SetResolution(Image.HorizontalResolution, Image.VerticalResolution);
                    ResizeImage = newImage;
                    pictureBox.Image = newImage;
                    DisplayMessage(txtMessageImage, MessageDefinition.ResizeImageSuccess, Color.Green);
                }
                catch (Exception e)
                {
                    DisplayMessage(txtMessageImage, e.Message, Color.Red);
                }
            };

            btnOriginal.Click += (sender, args) =>
            {
                try
                {
                    ResizeImage = Image;
                    pictureBox.Image = Image;
                    txtWidthImage.Text = Image.Width.ToString();
                    txtHeightImage.Text = Image.Height.ToString();
                    DisplayMessage(txtMessageImage, MessageDefinition.BackOriginalImageSuccess, Color.Green);
                }
                catch (Exception e)
                {
                    DisplayMessage(txtMessageImage, e.Message, Color.Red);
                }
                
            };

            //Button Convert on click event handle
            btnConvert.Click += (sender, args) =>
            {
                string width = txtWidthImage.Text;
                string height = txtHeightImage.Text;
                int widthNum;
                int heightNum;
                if (string.IsNullOrEmpty(width))
                {
                    DisplayMessage(txtMessageImage, MessageDefinition.WidthImageEmpty, Color.Red);
                    return;
                }
                if (string.IsNullOrEmpty(height))
                {
                    DisplayMessage(txtMessageImage, MessageDefinition.HeightImageEmpty, Color.Red);
                    return;
                }
                if (int.TryParse(width, out widthNum) == false)
                {
                    DisplayMessage(txtMessageImage, MessageDefinition.WidthImageIsNotNumber, Color.Red);
                    return;
                }
                if (int.TryParse(height, out heightNum) == false)
                {
                    DisplayMessage(txtMessageImage, MessageDefinition.HeightImageIsNotNumber, Color.Red);
                    return;
                }
                if (widthNum <= 0 || heightNum <= 0)
                {
                    DisplayMessage(txtMessageImage, MessageDefinition.InvalidNumber, Color.Red);
                    return;
                }
                try
                {
                    using (MemoryStream ms = new MemoryStream())
                    {
                        // Convert Image to byte[]
                        ResizeImage.Save(ms, ImageFormat);
                        byte[] imageBytes = ms.ToArray();

                        // Convert byte[] to Base64 String
                        string base64String = Convert.ToBase64String(imageBytes);
                        txtBase64.Text = base64String;
                        if(string.IsNullOrEmpty(base64String))
                            DisplayMessage(txtMessageImage, MessageDefinition.ConvertImageFail, Color.Red);
                        else
                            DisplayMessage(txtMessageImage, MessageDefinition.ConvertImageSuccess, Color.Green);

                    }
                }
                catch (Exception e)
                {
                    DisplayMessage(txtMessageImage, e.Message, Color.Red);
                }
                
            };
            #endregion

            #region TAB PAGE 4
            //button Convert on click event handle
            btnStringBase64Convert.Click += (sender, args) =>
            {
                string stringData = txtStringConvert.Text;
                string base64Data = txtBase64Convert.Text;
                if (string.IsNullOrEmpty(stringData) && string.IsNullOrEmpty(base64Data))
                {
                    DisplayMessage(txtMessageStringBase64Convert, MessageDefinition.StringOrBase64Empty, Color.Red);
                    return;
                }
                if (string.IsNullOrEmpty(stringData) && !string.IsNullOrEmpty(base64Data))
                    focusedTextBoxFlag = MessageDefinition.FocusedBase64;
                if (!string.IsNullOrEmpty(stringData) && string.IsNullOrEmpty(base64Data))
                    focusedTextBoxFlag = MessageDefinition.FocusedString;
                string data;
                try
                {
                    if (focusedTextBoxFlag == MessageDefinition.FocusedString)
                    {
                        data = txtStringConvert.Text;
                        txtBase64Convert.Text = Convert.ToBase64String(Encoding.UTF8.GetBytes(data));
                        DisplayMessage(txtMessageStringBase64Convert, MessageDefinition.ConvertStringToBase64Success,
                            Color.Green);
                        return;
                    }
                }
                catch (Exception e)
                {
                    DisplayMessage(txtMessageStringBase64Convert,
                        "String Field" + Environment.NewLine + e.Message, 
                        Color.Red);
                }
                try
                {
                    data = txtBase64Convert.Text;
                    txtStringConvert.Text = Encoding.UTF8.GetString(Convert.FromBase64String(data));
                    DisplayMessage(txtMessageStringBase64Convert, MessageDefinition.ConvertBase64ToStringSuccess, Color.Green);
                }
                catch (Exception e)
                {
                    DisplayMessage(txtMessageStringBase64Convert, 
                        "Base64 Field\n" + Environment.NewLine + e.Message, Color.Red);
                }
            };

            //Textbox String on focus event handle
            txtStringConvert.GotFocus += (o, eventArgs) =>
            {
                focusedTextBoxFlag = MessageDefinition.FocusedString;
            };

            //Textbox String on focus event handle
            txtBase64Convert.GotFocus += (o, eventArgs) =>
            {
                focusedTextBoxFlag = MessageDefinition.FocusedBase64;
            };
            #endregion
            //Menu ItemExit Event Click Handle
            menuItemExit.Click += (sender, args) =>
            {
                Application.Exit();
            };
            //Menu Item About Event Click Handle
            menuItemAbout.Click += (sender, args) =>
            {
                MessageBox.Show(MessageDefinition.ApplicationAbout, MessageDefinition.AppicationName, MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            };
            //Menu Item Tips Event Click Handle
            menuItemTips.Click += (sender, args) =>
            {
                MessageBox.Show(MessageDefinition.ApplicationTips, MessageDefinition.AppicationName, MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            };
        }

        /*
         * CLI PROCESS
         * Current Command: .\DeEnCrypt.exe rsa genxmlprivatekey [{keysize=<key-size>} | {filename=<file-name>}]
         * Default: 
         *      keysize=2048
         *      filename = ConnectionEncryptionKeys.xml
         */
        public Form2(string[] args)
        {
            try
            {
                int keySize = 2048;
                string privateKeyFileName = MessageDefinition.PrivateKeyFileName;

                if (args[0].ToLower() != MessageDefinition.RSA)
                    return;

                if (args[1].ToLower() != MessageDefinition.GenXMLKey)
                    return;

                for (int i = 2; i < args.Length; i++)
                {
                    bool rs = CLISplitKeyValue(args[i], out string key, out string value);
                    if (rs == false)
                        return;
                    switch (key.ToLower())
                    {
                        case MessageDefinition.KeySize:
                            keySize = Convert.ToInt32(value);
                            break;
                        case MessageDefinition.FileName:
                            if (string.IsNullOrEmpty(value))
                                break;
                            privateKeyFileName = value + ".xml";
                            break;
                    }
                }
                //Generate private key for RSA Algorithm
                RSAAlgorithmHandle.GenerateKeyXML(keySize, out string publicKey, out string privateKey);
                // Check if file already exists. If yes, delete it. 
                if (File.Exists(privateKeyFileName))
                {
                    File.Delete(privateKeyFileName);
                }
                // Create a new file 
                using (FileStream fs = File.Create(privateKeyFileName))
                {
                    // Add some text to file
                    Byte[] privKeyByte = new UTF8Encoding(true).GetBytes(privateKey);
                    fs.Write(privKeyByte, 0, privKeyByte.Length);
                }
            }
            catch (Exception e)
            {
                string fileName = "Log_" + DateTime.Today.ToString("ddMMyyyy") + ".txt";
                // Check if file already exists. If yes, delete it. 
                if (File.Exists(fileName))
                {
                    File.Delete(fileName);
                }
                // Create a new file 
                using (FileStream fs = File.Create(fileName))
                {
                    // Add some text to file
                    Byte[] privKeyByte = new UTF8Encoding(true).GetBytes(e.ToString());
                    fs.Write(privKeyByte, 0, privKeyByte.Length);
                }
            }
        }

        private bool CLISplitKeyValue(string keyValue, out string key, out string value)
        {
            key = string.Empty;
            value = string.Empty;
            string[]keyValueArray = keyValue.Split(new[]{'='}, 2);
            if (keyValue.Length == keyValueArray[0].Length)
                return false;
            key = keyValueArray[0];
            value = keyValueArray[1];
            //return (keyValue.Length == keyValueArray[0].Length) ? keyValueArray[0] : string.Empty;
            return true;
        }
        
        private bool CheckValidateTwoWay()
        {
            if (string.IsNullOrWhiteSpace(txtKey.Text))
            {
                DisplayMessage(txtBoxMessage, MessageDefinition.KeyEmpty, Color.Red);
                return false;
            }
            if (string.IsNullOrEmpty(txtInputText.Text))
            {
                DisplayMessage(txtBoxMessage, MessageDefinition.InputTextEmpty, Color.Red);
                return false;
            }
            return true;
        }

        private bool CheckValidateOneWay()
        {
            if (string.IsNullOrEmpty(txtInputText.Text))
            {
                DisplayMessage(txtBoxMessage, MessageDefinition.InputTextEmpty, Color.Red);
                return false;
            }
            return true;
        }

        private void DisplayMessage(TextBox textbox, string message, Color color)
        {
            textbox.Clear();
            textbox.Text = message;
            textbox.ForeColor = color;
        }

        private bool CheckValidateBeforeHandle()
        {
            string cbxAlgorithm = this.cbxAlgorithm.SelectedItem.ToString();
            foreach (string algorithm in OneWayAlgorithm)
            {
                if (cbxAlgorithm == algorithm)
                {
                    return CheckValidateOneWay();
                }
            }
            return CheckValidateTwoWay();
        }
        
        private void TextDoubleClick(TextBox textbox)
        {
            textbox.DoubleClick += (sender, args) =>
            {
                textbox.SelectAll();
                textbox.Copy();
            };
        }

        /*
         * FUNCTIONS RESERVE FOR TAB 3
         */
        private void EnableAfterUploaded(bool enable)
        {
            txtWidthImage.Enabled = enable;
            txtHeightImage.Enabled = enable;
            btnResizeImage.Enabled = enable;
            txtBase64.Enabled = enable;
            btnConvert.Enabled = enable;
            btnOriginal.Enabled = enable;
        }
    }
}
