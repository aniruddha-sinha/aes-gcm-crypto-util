package com.crypto.aes.string.core;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
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

	private static final Charset UTF_8 = StandardCharsets.UTF_8;
	private static final int AES_KEY_BIT = 256;
	private static final int IV_LENGTH_BYTE = 16;

	private static final SecretKey secretKey = AesCryptoGCM.getAESKey(AES_KEY_BIT);
	private static final byte[] iv = AesCryptoGCM.getRandomNonce(IV_LENGTH_BYTE);
	
	public static String encrypt(String plainText) throws InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		return AesCryptoGCM.encryptWithPrefixIV(plainText.getBytes(UTF_8), secretKey, iv);
	}

	public static String decrypt(String encryptedText) throws Exception    {
		return AesCryptoGCM.decryptWithPrefixIV(encryptedText, secretKey, iv);
	}
}
