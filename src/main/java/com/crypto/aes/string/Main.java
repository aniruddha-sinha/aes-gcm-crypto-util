package com.crypto.aes.string;

import com.crypto.aes.string.core.AES;

public class Main {

	public static void main(String[] args) throws Exception {
		// encrypt
		long encryptTimeStart = System.currentTimeMillis();

		String plainText = "This /is/a/plain/text... consists special chars and backslashes \\ \\ \\ \\; I can put the string however I want; this simply works!!!! ";
		System.out.println("PlainText " + plainText);
		String encryptedText = AES.encrypt(plainText);

		long encryptTimeEnd = System.currentTimeMillis();

		System.out.println("Encrypted Text " + encryptedText);
		System.out.println("Encrypted Text Length  " + encryptedText.length());
		System.err.println((encryptTimeEnd - encryptTimeStart) / 1000.0 + " seconds");

		System.out.println("\n\n\n");

		// decrypt
		long decryptTimeStart = System.currentTimeMillis();

		String decryptedText = AES.decrypt(encryptedText);

		long decryptTimeEnd = System.currentTimeMillis();

		System.out.println("Decrypted Text " + decryptedText);

		System.out.println("is plain == decrypted ?? " + plainText.equalsIgnoreCase(decryptedText));

		System.err.println((decryptTimeEnd - decryptTimeStart) / 1000.0 + " seconds");
	}
}
