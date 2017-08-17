# DeEnCrypt
DeEnCrypt is developed for encrypt/decrypt your important data by using some common hash algorithm.
1. Other (include 3DES, AES, MD5, SHA-1, SHA-256, SHA-384, SHA-512)
- One Way: MD5, SHA-1, SHA-256, SHA-384, SHA-512
	+ Salt: Append to your data before hash (more security).
	+ Validate Data: 
		+ If Enable: it will compare between (Salt + Input Text) and Encrypted Text.
- Two Way: 3DES, AES
	+ Key Size: size of key when generate key.
	+ Padding Mode: Specifies the type of padding to apply when the message data block is shorter than the full number of bytes needed for a cryptographic operation.
		+ Note: For mode "None", 3DES requires at least 8 bytes whereas AES requires at least 16 bytes in input text.
	+ Key: Key for encrypt/decrypt.
- Input Text: Put your data to this place.
- Output Text: The output when you click Encrypt/Decrypt(only on 3DES, AES).
- Look at Message Field in the bottom after one action.
2. RSA
3. Image To Base 64
- After your image uploaded, you will be shown your image again.
- Resize(Optional): use it if you want to resize your image before convert to base64.
	+ Type width/height (Note: It maintains aspect ratio image)
	+ Click Resize: Resize image and show it after resize.
	+ Click Original: Back to your original image.
	+ Click Convert: Convert image to base64.
- Look at Message Field in the bottom after one action.
4. Convert between String and Base64
- Convert String to Base64:
	Type string in String field and click convert
- Convert Base64 to String:
	Type string in Base64 field and click convert
- Click Convert:
	+ If one of 2 field is empty, it will convert from non-empty field to empty field.
	+ If both are non-empty, it will convert from focused field to non-focus field.
- Look at Message Field in the bottom after one action.
