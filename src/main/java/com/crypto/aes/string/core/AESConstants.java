package com.crypto.aes.string.core;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class AESConstants {
	private AESConstants() {
		
	}

	// encryption algorithm
		public static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";

		// Length (in bits) of authentication tag – 128 bits (16 bytes)
		public static final int TAG_LENGTH_BIT = 128;

		public static final Charset UTF_8 = StandardCharsets.UTF_8;

		public static final String KEY_GEN_INSTANCE_NAME = "AES";

		public static final int AES_KEY_BIT = 256;
		
		public static final int IV_LENGTH_BYTE = 96;

		public static final String SECRET_KEY_TRANSFORMATION_ALGORITHM = "PBKDF2WithHmacSHA256";

		public static final String KEY_GEN_ERROR = "Could not determine algorithm AES";

}
