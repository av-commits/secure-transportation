package ch.avcommits.securetransportation;

import java.security.cert.X509Certificate;

public interface TrustedCaStore {
    public void addCa(String name, X509Certificate cert);
    public void validateCert(X509Certificate cert);
}
