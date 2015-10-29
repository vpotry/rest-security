package vpo.rest.app;

import java.util.HashSet;
import java.util.Set;

import vpo.rest.controller.RESTService;

public class RESTApplication extends javax.ws.rs.core.Application {

private Set<Object> singletons = new HashSet<Object>();
	public RESTApplication () {
	    singletons.add(new RESTService());
	}
	
	@Override
	public Set<Object> getSingletons() {
	    return singletons;
	}
}