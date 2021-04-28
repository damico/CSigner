package org.jdamico.scryptool.crypto;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.jdamico.scryptool.commons.TopLevelException;
import org.jdamico.scryptool.entities.PrivateKeyAndCertChain;

public abstract class CreateSignatureBase implements SignatureInterface
{
    private PrivateKey privateKey;
    private Certificate[] certificateChain;
    private String tsaUrl;
    private boolean externalSigning;
    private PKCS11_Helper pki;
    private String libLocation = null;
    private String pinCode;
    private KeyStore userKeyStore = null;

    /**
     * Initialize the signature creator with a keystore (pkcs12) and pin that should be used for the
     * signature.
     *
     * @param keystore is a pkcs12 keystore.
     * @param pin is the pin for the keystore / private key
     * @throws KeyStoreException if the keystore has not been initialized (loaded)
     * @throws NoSuchAlgorithmException if the algorithm for recovering the key cannot be found
     * @throws UnrecoverableKeyException if the given password is wrong
     * @throws CertificateException if the certificate is not valid as signing time
     * @throws IOException if no certificate could be found
     * @throws TopLevelException 
     */
    public CreateSignatureBase(File document, String libLocation, String pinCode) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, IOException, CertificateException, TopLevelException {
        
       
    	this.libLocation = libLocation;
    	this.pinCode = pinCode;
    	this.pki = new PKCS11_Helper();
    	
    	if (libLocation.length() == 0) {
			String errorMessage = "It is mandatory to choose a PCKS#11 native " +
					"implementation library for for smart card (.dll or .so file)!";
			throw new TopLevelException(errorMessage);
		}

		// Load the keystore from the smart card using the specified PIN code
		
		try {
			this.userKeyStore = pki.loadKeyStore(libLocation, pinCode);
			setCertificateChain(pki.getCertificates(userKeyStore));
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
    	
    }
    
    
    public final String getCertificateAbstract() {
    	Certificate[] certificates = getCertificateChain();
		Certificate certificate = certificates[0];

		String strCertificate = certificate.toString().replace("\n", "").replace("\r", "").replace(" OU", "").replace("O=", "ORG_").replace("C=", "COU_");

		String[] cnBlocks = strCertificate.split("CN=");

		String cnBlock = cnBlocks[1].split("=")[0].replaceAll(",", "");
		return "        Digital signature: "+cnBlock+" ("+cnBlocks[1].split("ORG_")[1].split(",")[0]+" "+cnBlocks[1].split("COU_")[1].split(",")[0]+")";
		
    }

    public final void setPrivateKey(PrivateKey privateKey)
    {
        this.privateKey = privateKey;
    }

    public final void setCertificateChain(final Certificate[] certificateChain)
    {
        this.certificateChain = certificateChain;
    }

    public Certificate[] getCertificateChain()
    {
        return certificateChain;
    }

    public void setTsaUrl(String tsaUrl)
    {
        this.tsaUrl = tsaUrl;
    }

    /**
     * SignatureInterface sample implementation.
     *<p>
     * This method will be called from inside of the pdfbox and create the PKCS #7 signature.
     * The given InputStream contains the bytes that are given by the byte range.
     *<p>
     * This method is for internal use only.
     *<p>
     * Use your favorite cryptographic library to implement PKCS #7 signature creation.
     * If you want to create the hash and the signature separately (e.g. to transfer only the hash
     * to an external application), read <a href="https://stackoverflow.com/questions/41767351">this
     * answer</a> or <a href="https://stackoverflow.com/questions/56867465">this answer</a>.
     *
     * @throws IOException
     */
    @Override
    public byte[] sign(InputStream docStream) throws IOException {
		byte [] returnData = null;
		
		PrivateKey privateKey = null;
		try {

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
     * Set if external signing scenario should be used.
     * If {@code false}, SignatureInterface would be used for signing.
     * <p>
     *     Default: {@code false}
     * </p>
     * @param externalSigning {@code true} if external signing should be performed
     */
    public void setExternalSigning(boolean externalSigning)
    {
        this.externalSigning = externalSigning;
    }

    public boolean isExternalSigning()
    {
        return externalSigning;
    }
}

