package org.jdamico.csigner;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.junit.Before;
import org.junit.Test;

public class GenRsaKeyPair {

	@Before
	public void setUp() throws Exception {
	}

	@Test
	public void test() throws IOException {
		
		RSAKeyPairGenerator g = new RSAKeyPairGenerator();
		g.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001),new SecureRandom(), 4096, 80));
		AsymmetricCipherKeyPair keypair = g.generateKeyPair();
		PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(keypair.getPrivate());
		byte[] privateKeyBytes = privateKeyInfo.toASN1Primitive().getEncoded();
		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(keypair.getPublic());
		byte[] publicKeyBytes = publicKeyInfo.toASN1Primitive().getEncoded();
		
	}

}
