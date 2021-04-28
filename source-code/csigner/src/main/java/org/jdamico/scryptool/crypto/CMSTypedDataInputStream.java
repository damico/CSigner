package org.jdamico.scryptool.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSTypedData;

public class CMSTypedDataInputStream implements CMSTypedData {
	InputStream in;

	public CMSTypedDataInputStream(InputStream is) {
		in = is;
	}

	public ASN1ObjectIdentifier getContentType() {
		return PKCSObjectIdentifiers.data;
	}


	public Object getContent() {
		return in;
	}


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
