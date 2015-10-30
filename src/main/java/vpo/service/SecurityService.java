package vpo.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Properties;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.core.MediaType;

import org.jboss.resteasy.security.smime.SignedOutput;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import vpo.conf.RestSecPropeties;

/**
 * !NOTE: very initial test version!
 * 
 * Provides content [en|de]cryption methods &
 * content signing.
 * 
 * TODO: keystore management, client secret storing
 * TODO: Client specific secret requires authentication
 * 
 * @author vpotry
 *
 */
public class SecurityService {
	private static X509Certificate xcert;
	private static KeyPair keypair;
	private static SecurityService instance;
	
	
	/**
	 * 
	 * @throws Exception
	 */
	private SecurityService() throws Exception {
		
		InputStream is = this.getClass().getResourceAsStream("/application.properties");
		Properties props = new Properties();
		props.load(is);
		String securityfile = props.getProperty("security.properyfile.location");
		
		RestSecPropeties securityProperties = new RestSecPropeties(securityfile);
		loadKeyStore(securityProperties.getKeyStoreFilePath());
		is.close();
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
	 * TODO: Keystore / password & keystore alias handling :)
	 * 
	 * @param storeFile
	 * @throws Exception
	 */
	private void loadKeyStore(String storeFile) throws Exception {
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
	
	/**
	 * Random secret for symmetric key encrypt/decrypt
	 * 
	 * @return Random secret key
	 * @throws NoSuchAlgorithmException
	 */
	public byte[] createRndSecretKey() throws NoSuchAlgorithmException {
		KeyGenerator kgen=KeyGenerator.getInstance("AES");
		SecureRandom sr=SecureRandom.getInstance("SHA1PRNG");
		sr.setSeed(SecureRandom.getSeed(128));
		kgen.init(128,sr);
		
		SecretKey skey=kgen.generateKey();
		return skey.getEncoded();
	}
	
	/**
	 * Get (TODO:stored) client-specific secret for 
	 * encrypt/decrypt
	 * 
	 * TODO: clientName not handled yet
	 * 
	 * @param clientName
	 * @return Secret for client x
	 * @throws NoSuchAlgorithmException
	 */
	public byte[] getSecretKey(String clientName) throws NoSuchAlgorithmException {
		KeyGenerator kgen=KeyGenerator.getInstance("AES");
		SecureRandom sr=SecureRandom.getInstance("SHA1PRNG");
		sr.setSeed(SecureRandom.getSeed(256));
		kgen.init(128,sr);
		
		SecretKey skey=kgen.generateKey();
		return skey.getEncoded();
	}
	
	/**
	 * Create signed output for given data
	 * 
	 * @param data 
	 * @param datatype  MediaType of the data
	 * @return SignedOutput
	 */
	public SignedOutput createSignedOutput(Object data, MediaType datatype) {
		SignedOutput output = new SignedOutput(data, datatype);
        output.setCertificate(getXcert());
        output.setPrivateKey(getKeyPair().getPrivate());
        return output;
	}
	
	/**
	 * Encrypt data
	 * 
	 * @param data
	 * @param transformation
	 * @return Base64 encoded crypted message
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public String encryptBase64(String data, String transformation) throws InvalidKeyException, NoSuchAlgorithmException, 
		NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		
		Cipher encrypt=Cipher.getInstance(transformation);
		encrypt.init(Cipher.ENCRYPT_MODE, getKeyPair().getPrivate());
		
		BASE64Encoder encoder = new BASE64Encoder();
		String base64Crypted = encoder.encode(encrypt.doFinal(data.getBytes()));
		
		return base64Crypted;
	}

	/**
	 * Decrypt data
	 * 
	 * @param encBase64Str  Base64 encoded crypted message
	 * @param transformation
	 * @return decrypted message
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws IOException
	 */
	public byte[] decryptBase64(String encBase64Str, String transformation) throws InvalidKeyException, NoSuchAlgorithmException, 
		NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		
		BASE64Decoder decoder = new BASE64Decoder();
		
		byte[] encData = decoder.decodeBuffer(encBase64Str);
		
		Cipher decrypt=Cipher.getInstance("RSA");
	    decrypt.init(Cipher.DECRYPT_MODE, getKeyPair().getPublic());
	    return decrypt.doFinal(encData);
	}

	/**
	 * 
	 * @param encBytes
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public byte[] decrypt(byte[] encBytes) throws InvalidKeyException, NoSuchAlgorithmException, 
		NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		
		Cipher decrypt=Cipher.getInstance("RSA");
	    decrypt.init(Cipher.DECRYPT_MODE, getKeyPair().getPublic());
	    return decrypt.doFinal(encBytes);
	}
	
	/**
	 * 
	 * @param klazz
	 * @param secKey
	 * @param transformation (default "AES")
	 * @return
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws InvalidKeyException 
	 */
	public byte[] encryptWithSymkey(byte[] data, byte[] secKey, String transformation) throws NoSuchAlgorithmException, 
					NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		if(transformation == null)
			transformation = "AES";
		
		Key secretKey = new SecretKeySpec(secKey, transformation);
		Cipher cipher = Cipher.getInstance(transformation);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		
		return cipher.doFinal(data);
	}
	
	/**
	 * Decrypt (symkey) encrypted data
	 * 
	 * @param encData
	 * @param secKey known by the encoder and decoder
	 * @param transformation (default "AES")
	 * @return decrypted message
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public byte[] decryptWithSymkey(byte[] encData, byte[] secKey, String transformation) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
		if(transformation == null)
			transformation = "AES";
		
		Key secretKey = new SecretKeySpec(secKey, transformation);
		Cipher dec = Cipher.getInstance(transformation);
		dec.init(Cipher.DECRYPT_MODE, secretKey);
		
		return dec.doFinal(encData);
	}
}
