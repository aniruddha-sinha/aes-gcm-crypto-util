package com.crypto.aes.string.core;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class AES {
	private AES() {

	}

	private static final SecretKey secretKey = AesCryptoGCM.getAESKey(AESConstants.AES_KEY_BIT);
	private static final byte[] iv = AesCryptoGCM.getRandomNonce(AESConstants.IV_LENGTH_BYTE);
	
	public static String encrypt(String plainText) throws InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		return AesCryptoGCM.encryptWithPrefixIV(plainText.getBytes(AESConstants.UTF_8), secretKey, iv);
	}

	public static String decrypt(String encryptedText) throws Exception    {
		return AesCryptoGCM.decryptWithPrefixIV(encryptedText, secretKey, iv);
	}
}
