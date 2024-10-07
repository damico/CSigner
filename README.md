# CSigner

An application written in Java to work with smartcards to embed signatures on PDF, it is also possible to sign other file formats - in this case the signatures are generated on a distinct file.
This project contains the source code to study case, javadocs and CSigner.exe use and its functions.
- Is important to note, that this project was started to provide an open-source alternative to sign PDF documents with A3 digital certificates based on Brazil's PKI, from ICP-Brasil chain (aka e-CPF and e-CNPJ). A3 digital certificates are stored inside hardware devices, cryptographic tokens or smart cards.
- These kind of hardware devices are accessible through a PKCS #11 standard. The implementation of these standard was done using Sun PKCS#11 Provider and specific .DLLs ans .SOs offered by the hardware manufacturers.
- The signature itself is generated through CMS/PKCS#7 standard that provides the capability to both sign and envelope a message, using a private key and certificate from a secure device. Once the application creates a CMSSignedData object (with BouncyCastle API) it is possible to generate a signed PDF file using Apache PDFBox library.

### How to Test/Use

```
git clone https://github.com/damico/CSigner
cd CSigner/source-code/csigner
mvn clean install package -DskipTests
java -jar target/csigner-0.0.1-SNAPSHOT-jar-with-dependencies.jar
```
**This program has 6 operations:**

- OPERATION 0: **Sign using smart card.** [Parameters: path-to-conf-file operation-number source-file smart-card-pin ] In this case, source-file is the file to be signed.
- OPERATION 1: **Verify signature using smart card.** [Parameters: path-to-conf-file operation-number source-file smart-card-pin path-to-base64-signature-file] In this case, source-file is the file signed.
- OPERATION 2: **Encrypt using smart card.** [Parameters: path-to-conf-file operation-number source-file smart-card-pin ] In this case, source-file is the file to be encrypted.
- OPERATION 3: **Decrypt using smart card.** [Parameters: path-to-conf-file operation-number source-file smart-card-pin ] In this case, source-file is the file to be decrypted.
- OPERATION 4: **Get certificate from smart card and save to a file.** [Parameters: path-to-conf-file operation-number source-file smart-card-pin ] In this case, source-file is the file path where the certificate will be saved.
- OPERATION 5: **Verify signature using saved certificate.** [Parameters: path-to-conf-file operation-number source-file path-to-file-signed path-to-base64-signature-file] In this case, source-file is the file path where the certificate was saved.

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
