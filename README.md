# CSigner

An application written in Java to work with smartcards to embed signatures on PDF, it is also possible to sign other file formats - in this case the signatures are generated on a distinct file.
This project contains the source code to study case, javadocs and CSigner.exe use and its functions.
- Is important to note, that this project was started to provide an open-source alternative to sign PDF documents with A3 digital certificates based on Brazil's PKI, from ICP-Brasil chain (aka e-CPF and e-CNPJ). A3 digital certificates are stored inside hardware devices, cryptographic tokens or smart cards.
- These kind of hardware devices are accessible through a PKCS #11 standard. The implementation of these standard was done using Sun PKCS#11 Provider and specifi .DLLs ans .SOs offered by the hardware manufacturers.

--

### Dependencies
- bcmail (from BouncyCastle under MIT License)
- bcpkix (from BouncyCastle under MIT License)
- bcprov (from BouncyCastle under MIT License)
- commons-codec (from Apache under Apache v2 License)
- commons-logging (from Apache under Apache v2 License)
- log4j (from Apache under Apache v2 License)
- pdfbox (from Apache under Apache v2 License)

--

### License

- CSigner is licensed under *Apache License Version 2.0* (http://opensource.org/licenses/Apache-2.0)
