package com.crypto.aes.password.core;

public class AES {

	public static String encrypt(String plainText) throws Exception {
		return AESCryptoGCMPkcs.encrypt(plainText);
	}
	
	public static String decrypt(String cipherText) throws Exception {
		return AESCryptoGCMPkcs.decrypt(cipherText);
	}
}
