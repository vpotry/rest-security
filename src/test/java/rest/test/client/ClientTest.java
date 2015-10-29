package rest.test.client;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.jboss.resteasy.client.ClientRequest;
import org.jboss.resteasy.security.smime.EnvelopedInput;

import vpo.service.SecurityService;

/**
 * TODO: unit test cases
 * 
 * @author vpotry
 *
 */
public class ClientTest {
	// Standalone test
	public static void main(String[] argv) throws Exception {
		ClientRequest request = new ClientRequest("http://localhost:9900/restsec/rest/list/encrypted/c:");
		EnvelopedInput input = request.getTarget(EnvelopedInput.class);
		
		
		X509Certificate cert = SecurityService.getInstance().getXcert();
		PrivateKey pk = SecurityService.getInstance().getKeyPair().getPrivate();
		String resp = (String)input.getEntity(String.class, pk, cert);
		
		System.out.println(resp);
	}
}
