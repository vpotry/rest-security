package vpo.rest.controller;
 
import java.util.*;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;

import org.jboss.resteasy.security.smime.EnvelopedOutput;

import vpo.domain.FileItem;
import vpo.service.FileService;
import vpo.service.SecurityService;

import com.google.gson.Gson;

/**
 * 
 * @author vpotry
 *
 */
@Path("/list")
public class RESTService  {
     
	@GET
    @Path("/plain/{path}")
    @Produces(MediaType.APPLICATION_JSON)
	public String getPlainFileList(@PathParam("path") String path) {
    	List <FileItem> list = FileService.listFiles(path);     
    	return new Gson().toJson(list);
    }
    
     
    @GET
    @Path("/encrypted/{path}")
    @Produces("application/pkcs7-mime")
    public EnvelopedOutput getEncryptedFileList(@PathParam("path") String path) {
    	List <FileItem> list = FileService.listFiles(path); 
    	EnvelopedOutput output = new EnvelopedOutput(new Gson().toJson(list), MediaType.APPLICATION_JSON);
      
    	try {
    	   output.setCertificate(SecurityService.getInstance().getXcert());
    	} catch (Exception e) {
    		// TODO Auto-generated catch block
    		e.printStackTrace();
    		output = new EnvelopedOutput("Server Internal Error",  MediaType.TEXT_PLAIN);
    	}
    	return output;
	}
    
    @GET
    @Path("/signed/{path}")
    public EnvelopedOutput getSignedFileList(@PathParam("path") String path) {  
    	List <FileItem> list = FileService.listFiles(path);
    	EnvelopedOutput output = new EnvelopedOutput(new Gson().toJson(list), MediaType.APPLICATION_JSON);
       
    	try {
			output.setCertificate(SecurityService.getInstance().getXcert());
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			output = new EnvelopedOutput("Server Internal Error",  MediaType.TEXT_PLAIN);
		}
       
    	return output;
    }

   /* @POST
    public void postData(EnvelopedInput<String> input)
    {
       String str = input.getEntity(SecurityService.getInstance().getXcert(), SecurityService.getInstance().getKeyPair().getPrivate();
    }*/
} 