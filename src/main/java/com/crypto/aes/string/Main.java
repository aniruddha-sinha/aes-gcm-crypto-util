package com.crypto.aes.string;

public class Main {
	public static void main(String[] args) throws Exception {
		String plainText = "This /is/a/plain/text... consists special chars and backslashes \\ \\ \\ \\ ";
		System.out.println("PlainText " + plainText);
		
		String encryptedText = AES.encrypt(plainText);
		System.out.println("Encrypted Text " + encryptedText);
		System.out.println("Encrypted Text Length  " + encryptedText.length());
		
		
		System.out.println("\n\n\n");
		
		String decryptedText = AES.decrypt(encryptedText);
		System.out.println("Decrypted Text "+ decryptedText);
		
		
		System.out.println("is plain == decrypted ?? " + plainText.equalsIgnoreCase(decryptedText) );
	}
}
