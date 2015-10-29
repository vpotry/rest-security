package vpo.domain;
 
import javax.xml.bind.annotation.XmlRootElement;
 
@XmlRootElement
public class FileItem {
 
    private String parent;
    private String name;
    private long size;
     
    public FileItem() {   
    }
    
    public FileItem(String parent, String name, long size) {
        this.setParent(parent);
        this.name = name;
        this.setSize(size);
    }
     
    public String getName() {
       return name;
    }
     
    public void setName(String name) {
       this.name = name;
    }

	public String getParent() {
		return parent;
	}

	public void setParent(String parent) {
		this.parent = parent;
	}

	public long getSize() {
		return size;
	}

	public void setSize(long size) {
		this.size = size;
	}

 
}