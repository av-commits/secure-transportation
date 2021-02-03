package ch.avcommits.securetransportation;

import javax.security.auth.x500.X500PrivateCredential;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public interface CryptoOperations {
    X500PrivateCredential generateSelfSignedCred(String certName);
    X500PrivateCredential generateRequestCred(String certName, X500PrivateCredential caCred);

    byte[] encryptCmsData(byte[] data, X509Certificate encryptionCertificate);
    byte[] decryptCmsData(byte[] encryptedData, PrivateKey decryptionKey);
}
