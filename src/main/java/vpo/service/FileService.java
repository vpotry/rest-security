package vpo.service;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import vpo.domain.FileItem;

public class FileService {
	public static List<FileItem> listFiles(String path) {
		File[] list = new File(path).listFiles();
		
		List <FileItem> fList = new ArrayList<FileItem>();
		
		for(File f : list) {
			if(!f.isDirectory()) {
				fList.add(new FileItem(f.getParent(), f.getName(), f.length()));
			}
		}
		
		return fList;
	}
}
