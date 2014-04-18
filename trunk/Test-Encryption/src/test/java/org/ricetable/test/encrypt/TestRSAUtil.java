package org.ricetable.test.encrypt;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.unitils.reflectionassert.ReflectionAssert.assertReflectionEquals;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import org.junit.Test;

public class TestRSAUtil {
	RSAUtil util = null;
	
	@Test
	public void testMakeObject(){
		util = RSAUtil.getInstance();
		assertReflectionEquals(RSAUtil.getInstance(), util);
	}
	
	@Test
	public void testMakeKey(){
		testMakeObject();
		KeyPair keyPair1 = null;
		KeyPair keyPair2 = null;
		try {
			keyPair1 = util.generatorKeyPair();
			keyPair2 = util.generatorKeyPair();
			
			if(keyPair1 == null){
				fail();
			}
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			fail();
		}
		
		if(keyPair1 instanceof KeyPair){
			if(keyPair2 instanceof KeyPair){
				assertTrue(true);
			} else {
				fail();
			}
		} else {
			fail();
		}
	}
	
	@Test
	public void testCryption(){
		testMakeObject();
		String text = "abcdEfdg!@34";
		try {
			
			KeyPair keyPair = util.generatorKeyPair();
			PublicKey publicKey = keyPair.getPublic();
			PrivateKey privateKey= keyPair.getPrivate();
			
			String enc = util.encrypt(text, publicKey);
			assertNotEquals(text, enc);
			String dec = util.decrypt(enc, privateKey);
			assertEquals(text, dec);
			
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}
	}
	
	@Test
	public void testGenRSASpec(){
		testMakeObject();
		KeyPair keyPair = null;
		try {
			keyPair = util.generatorKeyPair();
			PublicKey publicKey = keyPair.getPublic();
			PrivateKey privateKey = keyPair.getPrivate();
			
			RSAPublicKeySpec publicSpec = util.getRSAPublicKeySpec(publicKey);
			if(publicSpec instanceof RSAPublicKeySpec){
				assertTrue(true);
			} else {
				fail();
			}
			
			RSAPrivateKeySpec privateSpec = util.getRSAPrivateKeySpec(privateKey);
			if(privateSpec instanceof RSAPrivateKeySpec){
				assertTrue(true);
			} else {
				fail();
			}
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}
		
	}
}