package org.ricetable.testAes;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Base64;

/**
 * AESUtil class<br/>
 * - AES 128 / 256-CBC Encryption Util
 * 
 * @author libedi
 *
 */
public class AESUtil {
	
	private static final int KEY_SIZE_128 = 128;
	private static final int KEY_SIZE_256 = 256;
	@Deprecated
	private static final String SECRET_KEY_256 = "a2b4c6d8e0f2948b3840f5e7d6c8b0a1";
	private static final String IV_128 = "2d9587b0c1d37a6e";
	private static final String IV_256 = "9c8476a8b0c2645a719fe2045d7a90ea";
	
	private AESUtil(){
		
	}
	// Implement Singleton using Inner Class
	private static class AESUtilHolder{
		static final AESUtil instance = new AESUtil();
	}
	public static AESUtil getInstance(){
		return AESUtilHolder.instance;
	}
	
	/**
	 * generatorKey()<br/>
	 * - generate random SecretKey Object
	 * 
	 * @param keySize	Secret key size 128/256 bit
	 * @return	SecretKey Object
	 * @throws NoSuchAlgorithmException
	 */
	private SecretKey generatorSecretKey(int keySize) throws NoSuchAlgorithmException{
		SecretKey secretKey = null;
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");	// Pseudo-Random Number Generator
		generator.init(keySize, random);
		secretKey = generator.generateKey();
		return secretKey;
	}
	
	/**
	 * generatorKey128()<br/>
	 * - generate random SecretKey Object
	 * 
	 * @return	128bits SecretKey Object
	 * @throws NoSuchAlgorithmException
	 */
	public SecretKey generatorSecretKey128() throws NoSuchAlgorithmException{
		return generatorSecretKey(KEY_SIZE_128);
	}
	
	/**
	 * generatorKey256()<br/>
	 * - generate random SecretKey Object
	 * 
	 * @return 256bits SecretKey Object
	 * @throws NoSuchAlgorithmException
	 */
	public SecretKey generatorSecretKey256() throws NoSuchAlgorithmException{
		/* 
		 * 32byte (256bit)를 사용하면 java.security.InvalidKeyException: Illegal key size 예외발생.
		 * Unlimited JCE Policy 를 다운받아 $JAVA_HOME/jre/lib/security 에 복사해 덮어쓰기.
		 */
		return generatorSecretKey(KEY_SIZE_256);
	}
	
	/**
	 * encryptByAES128()
	 * 
	 * @param text	Plain text
	 * @param secretKey	SecretKey
	 * @return Encrypted AES 128bit data by Encoded Base64
	 * @throws UnsupportedEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	public String encryptByAES128(String text, SecretKey secretKey) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException{
		String encryptedText = null;
		byte[] bytes = text.getBytes("UTF-8");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(IV_128.getBytes()));
		encryptedText = new String(Base64.encodeBase64(cipher.doFinal(bytes)));
		return encryptedText;
	}
	
	/**
	 * encryptByAES256()
	 * 
	 * @param text	Plain text
	 * @param secretKey	SecretKey
	 * @return	Encrypted AES 256bit data by Encoded Base64
	 * @throws UnsupportedEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	public String encryptByAES256(String text, SecretKey secretKey) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException{
		String encryptedText = null;
		byte[] bytes = text.getBytes("UTF-8");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		/*
		 * Initialization Vector 값이 32byte (256bit) 사용하면
		 * java.security.InvalidAlgorithmParameterException: Wrong IV length: must be 16 bytes long 예외발생.
		 * Unlimited JCE Policy 를 다운받아 $JAVA_HOME/jre/lib/security 에 복사해 덮어쓰기.
		 */
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(IV_256.getBytes()));
		encryptedText = new String(Base64.encodeBase64(cipher.doFinal(bytes)));
		return encryptedText;
	}
	
	/**
	 * decryptByAES128()
	 * 
	 * @param encryptedBase64Text
	 * @param secretKey
	 * @return	decrypted text
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws UnsupportedEncodingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	public String decryptByAES128(String encryptedBase64Text, SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException{
		String decryptedText = null;
		byte[] bytes = Base64.decodeBase64(encryptedBase64Text.getBytes());
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(IV_128.getBytes()));
		decryptedText = new String(cipher.doFinal(bytes), "UTF-8");
		return decryptedText;
	}
	
	/**
	 * decryptByAES256()
	 * 
	 * @param encryptedBase64Text
	 * @param secretKey
	 * @return	decrypted text
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws UnsupportedEncodingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	public String decryptByAES256(String encryptedBase64Text, SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException{
		String decryptedText = null;
		byte[] bytes = Base64.decodeBase64(encryptedBase64Text.getBytes());
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		/*
		 * Initialization Vector 값이 32byte (256bit) 사용하면
		 * java.security.InvalidAlgorithmParameterException: Wrong IV length: must be 16 bytes long 예외발생.
		 * Unlimited JCE Policy 를 다운받아 $JAVA_HOME/jre/lib/security 에 복사해 덮어쓰기.
		 */
		cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(IV_256.getBytes()));
		decryptedText = new String(cipher.doFinal(bytes), "UTF-8");
		return decryptedText;
	}
	

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}

}
