/********************************************************************************/
/* 																				*/
/* Copyright [2016]	Robson de Melo Silva,										*/
/* 					Vitoria Akemi Kanegae,										*/
/* 					Jose Ricardo de Oliveira Damico								*/
/* 																				*/
/* Licensed under the Apache License, Version 2.0 (the "License");				*/
/* you may not use this file except in compliance with the License.				*/
/* You may obtain a copy of the License at										*/
/* 																				*/
/*     http://www.apache.org/licenses/LICENSE-2.0								*/
/* 																				*/
/* Unless required by applicable law or agreed to in writing, software			*/
/* distributed under the License is distributed on an "AS IS" BASIS,			*/
/* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.		*/
/* See the License for the specific language governing permissions and			*/
/* limitations under the License.												*/
/*																				*/
/********************************************************************************/

package org.jdamico.csigner;

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.logging.Logger;

import org.apache.commons.codec.binary.Base64;

import org.jdamico.scryptool.commons.Constants;
import org.jdamico.scryptool.commons.ManageProperties;
import org.jdamico.scryptool.commons.TopLevelException;
import org.jdamico.scryptool.commons.Utils;
import org.jdamico.scryptool.crypto.PKCS11_Helper;
import org.jdamico.scryptool.entities.AppProperties;


public class Runtime {

	public static AppProperties appProperties = null;

	public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {


		if(args!=null && args.length > 3){
			String propertiesFilePath = args[0];

			try {
				appProperties = ManageProperties.getInstance().getAppProperties(propertiesFilePath);
			} catch (TopLevelException e) {
				System.err.println("********************************************************************************************");
				System.err.println("Unable to find properties file: "+propertiesFilePath);
				System.err.println("********************************************************************************************");
				System.exit(1);
			}
			
			String strOperation = args[1];
			String scPasswd = null;
			
			int operation = -1;
			try {
				operation = Integer.parseInt(strOperation);
			} catch (NumberFormatException e) {
				System.err.println("The third argument must be an integer (operation type)!");
				System.exit(1);
			}

			String srcFilePath = args[2];

			File srcFile = new File(srcFilePath);

			if(!srcFile.isDirectory()){

				PKCS11_Helper pki = new PKCS11_Helper();

				String signatureFilePath = null;
				switch (operation) {
				case 0:
					
					Utils.getInstance().handleVerboseLog(appProperties, 'i', Constants.OPER_0);
					try {
						scPasswd = args[3];
						pki.signSelectedFile(srcFile, scPasswd, appProperties.getLibPath());
					} catch (TopLevelException e1) {
						Utils.getInstance().handleVerboseLog(appProperties, 'e', e1.getMessage());
						System.exit(1);
					}
					break;

				case 1:
					
					Utils.getInstance().handleVerboseLog(appProperties, 'i', Constants.OPER_1);
					try {
						scPasswd = args[3];
						signatureFilePath = args[4];
						pki.verifyDocumentSignature(appProperties.getLibPath(), scPasswd, srcFile, signatureFilePath);
					} catch (IndexOutOfBoundsException e) {
						Utils.getInstance().handleVerboseLog(appProperties, 'e', "The fifth argument must be a b64 string (signature)!");
						System.exit(1);
					} catch (TopLevelException e) {

					}

					break;

				case 2:
					Utils.getInstance().handleVerboseLog(appProperties, 'i', Constants.OPER_2);
					try {
						scPasswd = args[3];
						pki.encryptSelectedFile(srcFile, scPasswd, appProperties.getLibPath());
					} catch (TopLevelException e) {
						Utils.getInstance().handleVerboseLog(appProperties, 'e', e.getMessage());
						System.exit(1);
					}
					break;

				case 3:
					Utils.getInstance().handleVerboseLog(appProperties, 'i', Constants.OPER_3);
					try {
						scPasswd = args[3];
						pki.decryptSelectedFile(srcFile, scPasswd, appProperties.getLibPath());
					} catch (TopLevelException e) {
						Utils.getInstance().handleVerboseLog(appProperties, 'e', e.getMessage());
						System.exit(1);
					}
					break;


				case 4:
					Utils.getInstance().handleVerboseLog(appProperties, 'i', Constants.OPER_4);
					try {
						scPasswd = args[3];
						pki.setCertificateByFile(srcFilePath, scPasswd, appProperties.getLibPath());
					} catch (TopLevelException e) {
						Utils.getInstance().handleVerboseLog(appProperties, 'e', e.getMessage());
						System.exit(1);
					}
					break;

				case 5:
					signatureFilePath = args[4];
					String signedFileFilePath =  args[3];
					Utils.getInstance().handleVerboseLog(appProperties, 'i', Constants.OPER_5);
					Certificate cert = pki.getCertificateByFile(srcFilePath);
					String strB64File = Utils.getInstance().readFile(new File(signatureFilePath));
					byte[] sig = Base64.decodeBase64(strB64File);
					byte[] doc = Utils.getInstance().readFileInByteArray(signedFileFilePath);
					boolean b = pki.verifyDocumentSignature(cert, doc, sig);
					System.out.println(b);
					break;

				default:
					break;

				}
			}else{
				System.err.println("The <source-file> must be a valid file path!");
				System.exit(1);
			}

		}else{
			System.err.println("Wrong arguments.");
			help();
			System.exit(1);
		}

		

	}

	public static void help(){
		String help		 = "This program has 6 operations:\n\n\n"
						 + Constants.OPER_0 + "\n\n"
						 + Constants.OPER_1 + "\n\n"
						 + Constants.OPER_2 + "\n\n"
						 + Constants.OPER_3 + "\n\n"
						 + Constants.OPER_4 + "\n\n"
						 + Constants.OPER_5 + "\n\n\n"
						 		+ "Remember, the program will not work without a configuration file. See an example of this kind o file, bellow:\n\n"
						 		+ "libpath="+Constants.WIN_COMMON_LIB+" or "+Constants.LINUX_COMMON_LIB+"\n"
						 		+ "verbose=yes\n"
						 		+ "log=yes\n";
		
		System.out.println(help);
	}
	
}
