package vpo.conf;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

public class RestSecPropeties extends Properties {

	private static final long serialVersionUID = 1L;
	
	public static final String PROPERTY_KEYSTORE_LOCATION = "keystore.location";
	
	public RestSecPropeties(String filename) throws FileNotFoundException, IOException {
		super();
		
		this.load(new FileInputStream(filename));
	}
	
	public String getKeyStoreFilePath() {
		return this.getProperty(PROPERTY_KEYSTORE_LOCATION);
	}
	
}
