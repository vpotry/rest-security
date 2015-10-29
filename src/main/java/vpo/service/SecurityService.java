package vpo.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.crypto.*;

import org.jboss.resteasy.security.smime.SignedOutput;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 * 
 * @author vpotry
 *
 */
public class SecurityService {
	private static X509Certificate xcert;
	private static KeyPair keypair;
	private static SecurityService instance;
	
	private SecurityService() throws Exception { 
		loadKeyStore(new File("D:\\project\\JBoss_Rest\\.keystore"));
	}
	
	/**
	 * 
	 * @return
	 * @throws Exception
	 */
	public static SecurityService getInstance() throws Exception {
		if(instance == null) {
			instance = new SecurityService();
		}
		return instance;
	}
	
	public X509Certificate getXcert() {
		return xcert;
	}
	
	public KeyPair getKeyPair() {
		return keypair;
	}
	
	/**
	 * 
	 * @param storeFile
	 * @throws Exception
	 */
	private void loadKeyStore(File storeFile) throws Exception {
		FileInputStream is = new FileInputStream(storeFile);

		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		keystore.load(is, "changeit".toCharArray());

		String alias = "localhost";

		Key key = keystore.getKey(alias, "changeit".toCharArray());
		
		if (key instanceof PrivateKey) {
			// Get Certificate
			xcert = (X509Certificate)keystore.getCertificate(alias);

			// Get public key
			PublicKey publicKey = xcert.getPublicKey();

			// Return a key pair; publickey-privatekey
			keypair = new KeyPair(publicKey, (PrivateKey) key);
		}
	}
	
	
	public SignedOutput createSignedOutput(String msg) {
		SignedOutput output = new SignedOutput("hello world", "text/plain");
        output.setCertificate(xcert);
        output.setPrivateKey(keypair.getPrivate());
        return output;
	}
	
	public String encrypt(String data) throws InvalidKeyException, NoSuchAlgorithmException, 
		NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		
		Cipher encrypt=Cipher.getInstance("RSA");
		encrypt.init(Cipher.ENCRYPT_MODE, getKeyPair().getPrivate());
		
		BASE64Encoder encoder = new BASE64Encoder();
		String base64Crypted = encoder.encode(encrypt.doFinal(data.getBytes()));
		
		return base64Crypted;
	}

	public byte[] decrypt(String encBase64Str) throws InvalidKeyException, NoSuchAlgorithmException, 
		NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		
		BASE64Decoder decoder = new BASE64Decoder();
		
		byte[] encData = decoder.decodeBuffer(encBase64Str);
		
		Cipher decrypt=Cipher.getInstance("RSA");
	    decrypt.init(Cipher.DECRYPT_MODE, getKeyPair().getPublic());
	    return decrypt.doFinal(encData);
	}

	public byte[] decrypt(byte[] encBytes) throws InvalidKeyException, NoSuchAlgorithmException, 
		NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		
		Cipher decrypt=Cipher.getInstance("RSA");
	    decrypt.init(Cipher.DECRYPT_MODE, getKeyPair().getPublic());
	    return decrypt.doFinal(encBytes);
	}
	
}
