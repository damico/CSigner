package org.jdamico.scryptool.crypto;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;

import javax.imageio.ImageIO;

import org.apache.pdfbox.exceptions.COSVisitorException;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.edit.PDPageContentStream;
import org.apache.pdfbox.pdmodel.graphics.xobject.PDJpeg;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.jdamico.scryptool.commons.TopLevelException;
import org.jdamico.scryptool.entities.PrivateKeyAndCertChain;

// TODO: Auto-generated Javadoc
/**
 * The Class EmbedSignature.
 */
public class EmbedSignature implements SignatureInterface {

	/** The document to be signed. */
	private File doc;
	
	/** The token pin code. */
	private String pinCode;
	
	/** The lib location, this represents a default path for a dll and can be changed. */
	private String libLocation = "C:/Windows/System32/aetpkss1.dll";
	
	/** The pki. */
	private PKCS11_Helper pki;
	
	/* (non-Javadoc)
	 * @see org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface#sign(java.io.InputStream)
	 */
	@Override
	public byte[] sign(InputStream docStream) throws IOException {
		byte [] returnData = null;
		pki = new PKCS11_Helper();
		PrivateKey privateKey = null;
		try {
			
			if (libLocation.length() == 0) {
				String errorMessage = "It is mandatory to choose a PCKS#11 native " +
						"implementation library for for smart card (.dll or .so file)!";
				throw new TopLevelException(errorMessage);
			}

			// Load the keystore from the smart card using the specified PIN code
			KeyStore userKeyStore = null;
			try {
				userKeyStore = pki.loadKeyStore(libLocation, pinCode);
			} catch (Exception ex) {
				String errorMessage = "Can not read the keystore from the smart card.\n" +
						"Possible reasons:\n" +
						" - The smart card reader in not connected.\n" +
						" - The smart card is not inserted.\n" +
						" - The PKCS#11 implementation library is invalid.\n" +
						" - The PIN for the smart card is incorrect.\n" +
						"Problem details: " + ex.getMessage();
				throw new TopLevelException(errorMessage, ex);
			}

			// Get the private key and its certification chain from the keystore
			PrivateKeyAndCertChain privateKeyAndCertChain = null;
			privateKeyAndCertChain = pki.getPrivateKeyAndCertChain(userKeyStore, null);

			// Check if the private key is available
			privateKey = privateKeyAndCertChain.mPrivateKey;
			if (privateKey == null) {
				String errorMessage = "Can not find the private key on the smart card.";
				throw new TopLevelException(errorMessage);
			}

			// Check if X.509 certification chain is available
			Certificate[] certChain = privateKeyAndCertChain.mCertificationChain;
			if (certChain == null) {
				String errorMessage = "Can not find the certificate on the smart card.";
				throw new TopLevelException(errorMessage);
			}			
			 
            ArrayList<X509CertificateHolder> signingChainHolder = new ArrayList<X509CertificateHolder>();
            
            for (int i = 0; i < certChain.length; i++) {
            	signingChainHolder.add(new X509CertificateHolder(certChain[i].getEncoded()));
			}
			
            Store certStore = new JcaCertStore(signingChainHolder);

            CMSTypedDataInputStream input = new CMSTypedDataInputStream(docStream);
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            ContentSigner sha512Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(pki.getProvider()).build(privateKey);

            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                    new JcaDigestCalculatorProviderBuilder().setProvider(pki.getProvider()).build()).build(sha512Signer, new X509CertificateHolder(certChain[0].getEncoded())
            ));
            gen.addCertificates(certStore);
            CMSSignedData signedData = gen.generate(input, false);
            
            returnData =  signedData.getEncoded(); 

		} catch (TopLevelException e) {
			e.printStackTrace();
		} catch (CMSException e) {
			e.printStackTrace();
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
		} catch (OperatorCreationException e) {
			e.printStackTrace();
		}
		return returnData;
	}

	/**
	 * Sign pdf.
	 *
	 * @param document the pdf to be signed 
	 * @param libLocatin the lib locatin
	 * @param pinCode the token pin code
	 * @throws IOException Signals that an I/O exception has occurred.
	 * @throws SignatureException the signature exception
	 * @throws SignatureException the signature exception
	 * @throws COSVisitorException the COS visitor exception
	 */
	public void signPDF(File document, String libLocatin, String pinCode) throws IOException,
	SignatureException, COSVisitorException, org.apache.pdfbox.exceptions.SignatureException{

		setDoc(document);
		setLibLocation(libLocatin);
		setPinCode(pinCode);
		
		//loads a byte array from a original document
	    byte inputBytes[] = IOUtils.toByteArray(new FileInputStream(doc.getPath()));
	    PDDocument pdDocument = PDDocument.load(new ByteArrayInputStream(inputBytes));
	    ByteArrayOutputStream os = new ByteArrayOutputStream();
	    pdDocument.save(os);
	    os.flush();        
	    pdDocument.close();
	    inputBytes = os.toByteArray(); 
	    pdDocument = PDDocument.load(new ByteArrayInputStream(inputBytes));
	    
	    //necessary to a valid signature
	    PDSignature signature = new PDSignature();
	    signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
	    signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
	    signature.setName("signer name");
	    signature.setSignDate(Calendar.getInstance());

	    //not necessary
	    signature.setLocation("signer location");
	    signature.setReason("reason for signature");

	    //adds the dictionary signature to the document
	    pdDocument.addSignature(signature, this);
		if (!(document != null && document.exists()))
			new RuntimeException("");
		if(!new File(doc.getParent()+"/signed").exists()){
			new File(doc.getParent()+"/signed").mkdir();
		}
	    File outputDocument = new File(document.getParent()+"/signed/" + document.getName());
	    ByteArrayInputStream fis = new ByteArrayInputStream(inputBytes);
	    FileOutputStream fos = new FileOutputStream(outputDocument);
	    byte[] buffer = new byte[8 * 1024];
	    int c;
	    
	    while ((c = fis.read(buffer)) != -1)
	    {
	        fos.write(buffer, 0, c);
	    }
	    fis.close();
	    FileInputStream is = new FileInputStream(outputDocument);
	    
	    //this method adds the signature to a PDF, the method sign(InputStream in) will be called
	    pdDocument.saveIncremental(is, fos);
	    
	    pdDocument.close();

	}

	/**
	 * Gets the doc.
	 *
	 * @return the doc
	 */
	public File getDoc() {
		return doc;
	}

	/**
	 * Sets the doc.
	 *
	 * @param doc the new doc
	 */
	public void setDoc(File doc) {
		this.doc = doc;
	}

	/**
	 * Gets the pin code.
	 *
	 * @return the pin code
	 */
	public String getPinCode() {
		return pinCode;
	}

	/**
	 * Sets the pin code.
	 *
	 * @param pinCode the new pin code
	 */
	public void setPinCode(String pinCode) {
		this.pinCode = pinCode;
	}

	/**
	 * Gets the lib location.
	 *
	 * @return the lib location
	 */
	public String getLibLocation() {
		return libLocation;
	}

	/**
	 * Sets the lib location.
	 *
	 * @param libLocation the new lib location
	 */
	public void setLibLocation(String libLocation) {
		this.libLocation = libLocation;
	}

	/**
	 * Gets the pki.
	 *
	 * @return the pki
	 */
	public PKCS11_Helper getPki() {
		return pki;
	}

	/**
	 * Sets the pki.
	 *
	 * @param pki the new pki
	 */
	public void setPki(PKCS11_Helper pki) {
		this.pki = pki;
	}
	

}

class CMSTypedDataInputStream implements CMSTypedData {
    InputStream in;

    public CMSTypedDataInputStream(InputStream is) {
        in = is;
    }

    @Override
    public ASN1ObjectIdentifier getContentType() {
        return PKCSObjectIdentifiers.data;
    }

    @Override
    public Object getContent() {
        return in;
    }

    @Override
    public void write(OutputStream out) throws IOException,
            CMSException {
        byte[] buffer = new byte[8 * 1024];
        int read;
        while ((read = in.read(buffer)) != -1) {
            out.write(buffer, 0, read);
        }
        in.close();
    }
}
