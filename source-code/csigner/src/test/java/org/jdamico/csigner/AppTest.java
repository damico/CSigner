package org.jdamico.csigner;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Scanner;

import org.jdamico.scryptool.commons.Constants;
import org.jdamico.scryptool.commons.TopLevelException;
import org.jdamico.scryptool.crypto.AddVisibleSignature;
import org.junit.Before;

public class AppTest {

	@Before
	public void setUp() throws Exception {
	}

	@org.junit.Test
	public void test() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, TopLevelException {
		File fileToBeDeleted = new File("dist/sample_signed.pdf");
		if(fileToBeDeleted !=null && fileToBeDeleted.exists() && fileToBeDeleted.isFile()) fileToBeDeleted.delete();
    	new AddVisibleSignature(new File("dist/sample.pdf"), Constants.LINUX_COMMON_LIB, getInput());
    	assertTrue(fileToBeDeleted.isFile());
	}
	
	public String getInput() {
		System.out.println("Type token password: ");
        Scanner sc = new Scanner(System.in);
        return sc.nextLine();
    }

}
