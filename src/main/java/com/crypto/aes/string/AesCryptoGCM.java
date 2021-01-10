package com.crypto.aes.string;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * 
 * @author Aniruddha Sinha
 * @since Jan 2021
 * 
 *        The AES-GCM inputs: - AES Secret key (256 bits) - IV – 96 bits (12
 *        bytes) - Length (in bits) of authentication tag – 128 bits (16 bytes)
 * 
 *        Remarks: It is ok for IV to be publicly known, the only secret is the
 *        key, keep it private and confidential.
 *
 */
public class AesCryptoGCM {
	private AesCryptoGCM() {

	}

	public static byte[] getRandomNonce(int numBytes) {
		byte[] nonce = new byte[numBytes];
		new SecureRandom().nextBytes(nonce);
		return nonce;
	}

	// AES secret key
	public static SecretKey getAESKey(int keysize) {
		KeyGenerator keyGen = null;
		SecretKey generatedKey = null;
		try {
			keyGen = KeyGenerator.getInstance(AESConstants.KEY_GEN_INSTANCE_NAME);
			keyGen.init(keysize, SecureRandom.getInstanceStrong());
			generatedKey = keyGen.generateKey();
		} catch (Exception e) {
			System.err.println(AESConstants.KEY_GEN_ERROR);
		}

		return generatedKey;
	}
	
	// AES-GCM needs GCMParameterSpec
	private static byte[] encrypt(byte[] pText, SecretKey secret, byte[] iv)
			throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

		Cipher cipher = Cipher.getInstance(AESConstants.ENCRYPT_ALGO);
		cipher.init(Cipher.ENCRYPT_MODE, secret, new GCMParameterSpec(AESConstants.TAG_LENGTH_BIT, iv));
		return cipher.doFinal(pText);

	}

	private static String decrypt(byte[] cText, SecretKey secret, byte[] iv)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

		Cipher cipher = Cipher.getInstance(AESConstants.ENCRYPT_ALGO);
		cipher.init(Cipher.DECRYPT_MODE, secret, new GCMParameterSpec(AESConstants.TAG_LENGTH_BIT, iv));
		byte[] plainText = cipher.doFinal(cText);
		return new String(plainText, AESConstants.UTF_8);

	}

	// prefix IV length + IV bytes to cipher text
	public static String encryptWithPrefixIV(byte[] pText, SecretKey secret, byte[] iv)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		byte[] cipherText = encrypt(pText, secret, iv);
		return Base64.getUrlEncoder()
				.encodeToString(ByteBuffer.allocate(iv.length + cipherText.length).put(iv).put(cipherText).array());
	}

	public static String decryptWithPrefixIV(String cipherText, SecretKey secret, byte[] iv) throws Exception {
		byte[] cText = Base64.getUrlDecoder().decode(cipherText.getBytes(AESConstants.UTF_8));
		ByteBuffer bb = ByteBuffer.wrap(cText);
		bb.get(iv);
		byte[] cipherTextRem = new byte[bb.remaining()];
		bb.get(cipherTextRem);
		return decrypt(cipherTextRem, secret, iv);

	}

}
