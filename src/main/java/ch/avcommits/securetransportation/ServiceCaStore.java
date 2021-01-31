package ch.avcommits.securetransportation;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.util.Collections;

@Slf4j
@Component
public class ServiceCaStore implements TrustedCaStore{

    private KeyStore trustedStore;

    public ServiceCaStore() {
        try {
            trustedStore = KeyStore.getInstance("JKS");
            trustedStore.load(null, null);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            log.error("Keystore creation failed", e);
        }
    }

    @Override
    public void addCa(String name, X509Certificate cert) {
        try {
            trustedStore.setCertificateEntry(name, cert);
            log.info("CA added: {}", name);
        } catch (KeyStoreException e) {
            log.error("Failed to add ca", e);
            throw new RuntimeException(e);
        }
    }

    @Override
    public void validateCert(X509Certificate cert) {
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
            CertPath certPath =
                    certificateFactory.generateCertPath(Collections.singletonList(cert));
            CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX", new BouncyCastleProvider());
            PKIXParameters parameters = new PKIXParameters(trustedStore);
            parameters.setRevocationEnabled(false);

            //PKIXCertPathValidatorResult validatorResult = (PKIXCertPathValidatorResult)
            certPathValidator.validate(certPath, parameters);
        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | InvalidAlgorithmParameterException | CertPathValidatorException e) {
            throw new RuntimeException(e);
        }
    }
}