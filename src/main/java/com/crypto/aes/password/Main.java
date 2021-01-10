package com.crypto.aes.password;

import com.crypto.aes.password.core.AES;

public class Main {
	public static void main(String[] args) throws Exception {
		long timeStart = System.currentTimeMillis();
		String plainText = "This /is/a/plain/text... consists special chars and backslashes \\ \\ \\ \\; I can put the string however I want; this simply works!!!! ";
		System.out.println("PlainText " + plainText);

		String encryptedText = AES.encrypt(plainText);
		System.out.println("Encrypted Text " + encryptedText);
		System.out.println("Encrypted Text Length  " + encryptedText.length());

		System.out.println("\n\n\n");

		String decryptedText = AES.decrypt(encryptedText);
		System.out.println("Decrypted Text " + decryptedText);

		System.out.println("is plain == decrypted ?? " + plainText.equalsIgnoreCase(decryptedText));

		long timeEnd = System.currentTimeMillis();

		System.err.println((timeEnd - timeStart) / 1000.0 + " seconds");
	}
}
