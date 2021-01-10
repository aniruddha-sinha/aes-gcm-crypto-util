package com.crypto.aes.password.core;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class AESConstants {
	private AESConstants() {
	}

	public static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";

	public static final int TAG_LENGTH_BIT = 128; // must be one of {128, 120, 112, 104, 96}
	public static final int IV_LENGTH_BYTE = 12;
	public static final int SALT_LENGTH_BYTE = 16;
	public static final Charset UTF_8 = StandardCharsets.UTF_8;
	public static final String SECRET_KEY_TRANSFORMATION_ALGORITHM = "PBKDF2WithHmacSHA256";
	public static final String KEY_GEN_INSTANCE_NAME = "AES";
	
	public static final String PASSWORD = "GPNframework9";
}
