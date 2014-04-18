package org.ricetable.test.encrypt;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;

/**
 * RSAUtil Class<br/>
 * - Util class using RSA cryptosystem Algorithm.<br/>
 * - Public Key is used for encrypting text.<br/>
 * - Private Key is used for decrypting text encrypted with the public key.
 * @author Park Sang Jun
 *
 */
public class RSAUtil {
	
	private static RSAUtil instance = null;
	
	private final String RSA = "RSA";
	private final int KEY_SIZE = 1024;
	
	private RSAUtil(){
		
	}
	public static RSAUtil getInstance() {
		if(instance == null){
			synchronized(RSAUtil.class){
				if(instance == null){
					instance = new RSAUtil();
				}
			}
		}
		return instance;
	}

	/**
	 * generatorKeyPair()
	 * 
	 * @return	RSA KeyPair Object
	 * @throws NoSuchAlgorithmException
	 */
	public KeyPair generatorKeyPair() throws NoSuchAlgorithmException {
		KeyPair keyPair = null;
		KeyPairGenerator generator = KeyPairGenerator.getInstance(RSA);
		generator.initialize(KEY_SIZE);
		keyPair = generator.generateKeyPair();
		return keyPair;
	}

	/**
	 * encrypt()
	 * 
	 * @param text	Plain text
	 * @param publicKey	Public Key used encryption
	 * @return	Base64-Text encrypted with Public key
	 * @throws UnsupportedEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public String encrypt(String text, PublicKey publicKey) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		String encryptedText = null;
		byte[] bytes = text.getBytes("UTF-8");
		Cipher cipher = Cipher.getInstance(RSA);
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		encryptedText = new String(Base64.encodeBase64(cipher.doFinal(bytes)));
		return encryptedText;
	}

	/**
	 * decrypt()
	 * 
	 * @param encryptedBase64Text	encrypted Base64-Text
	 * @param privateKey	Private Key
	 * @return	Decrypted Text
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws UnsupportedEncodingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public String decrypt(String encryptedBase64Text, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
		String decryptedText = null;
		byte[] bytes = Base64.decodeBase64(encryptedBase64Text.getBytes());
		Cipher cipher = Cipher.getInstance(RSA);
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		decryptedText = new String(cipher.doFinal(bytes), "UTF-8");
		return decryptedText;
	}
	
	/**
	 * getRSAPublicKeySpec()
	 * 
	 * @param publicKey	Public Key
	 * @return	RSAPublicKeySpec Object
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 */
	public RSAPublicKeySpec getRSAPublicKeySpec(PublicKey publicKey) throws InvalidKeySpecException, NoSuchAlgorithmException {
		RSAPublicKeySpec spec = null;
		spec = KeyFactory.getInstance(RSA).getKeySpec(publicKey, RSAPublicKeySpec.class);
		return spec;
	}
	
	/**
	 * getRSAPrivateKeySpec()
	 * 
	 * @param privateKey	Private Key
	 * @return	RSAPrivateKeySpec Object
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 */
	public RSAPrivateKeySpec getRSAPrivateKeySpec(PrivateKey privateKey) throws InvalidKeySpecException, NoSuchAlgorithmException {
		RSAPrivateKeySpec spec = null;
		spec = KeyFactory.getInstance(RSA).getKeySpec(privateKey, RSAPrivateKeySpec.class);
		return spec;
	}
	
	
}
