package org.ricetable.test.encrypt;

import static org.junit.Assert.assertEquals;
import static org.unitils.reflectionassert.ReflectionAssert.*;

import javax.crypto.SecretKey;

import org.junit.Test;
import org.ricetable.test.encrypt.AESUtil;

public class TestAESUtil {
	private AESUtil aes = null;
	
	@Test
	public void instanceTest(){
		aes = AESUtil.getInstance();
		assertReflectionEquals(AESUtil.getInstance(), aes);
	}
	
	@Test
	public void encryptTest(){
		instanceTest();
		String text = "abcd2134!@#$";
		try {
			SecretKey key = aes.generatorSecretKey128();
			String enc = aes.encryptByAES128(text, key);
			String dec = aes.decryptByAES128(enc, key);
			assertEquals(text, dec);
			
		} catch (Exception e){
			e.printStackTrace();
		}
		
	}
}
