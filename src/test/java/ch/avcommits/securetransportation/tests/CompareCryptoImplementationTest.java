package ch.avcommits.securetransportation.tests;

import ch.avcommits.securetransportation.CryptoBouncycastle;
import ch.avcommits.securetransportation.CryptoOpenssl;
import ch.avcommits.securetransportation.CryptoOperations;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500PrivateCredential;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

public class CompareCryptoImplementationTest {
    @Test
    public void opensslEncJavaDec() {
        CryptoOperations coKey = new CryptoBouncycastle();
        CryptoOperations coEnc = new CryptoOpenssl();
        CryptoOperations coDec = new CryptoBouncycastle();

        String data = "My Data";
        X500PrivateCredential kc = coKey.generateSelfSignedCred("signing");
        X500PrivateCredential req = coKey.generateRequestCred("req", kc);

        byte[] encData = coEnc.encryptCmsData(data.getBytes(StandardCharsets.UTF_8), req.getCertificate());
        byte[] clearData = coDec.decryptCmsData(encData, req.getPrivateKey());

        assertThat(new String(clearData, StandardCharsets.UTF_8)).isEqualTo(data);
    }

    @Test
    public void opensslDecOpensslEnc() {
        CryptoOperations coKey = new CryptoBouncycastle();
        CryptoOperations coEnc = new CryptoOpenssl();
        CryptoOperations coDec = new CryptoOpenssl();

        String data = "My Data";
        X500PrivateCredential kc = coKey.generateSelfSignedCred("signing");
        X500PrivateCredential req = coKey.generateRequestCred("req", kc);

        byte[] encData = coEnc.encryptCmsData(data.getBytes(StandardCharsets.UTF_8), req.getCertificate());
        byte[] clearData = coDec.decryptCmsData(encData, req.getPrivateKey());

        assertThat(new String(clearData, StandardCharsets.UTF_8)).isEqualTo(data);
    }

    @Test
    public void javaDecJavaEnc() {
        CryptoOperations coKey = new CryptoBouncycastle();
        CryptoOperations coEnc = new CryptoBouncycastle();
        CryptoOperations coDec = new CryptoBouncycastle();

        String data = "My Data";
        X500PrivateCredential kc = coKey.generateSelfSignedCred("signing");
        X500PrivateCredential req = coKey.generateRequestCred("req", kc);

        byte[] encData = coEnc.encryptCmsData(data.getBytes(StandardCharsets.UTF_8), req.getCertificate());
        byte[] clearData = coDec.decryptCmsData(encData, req.getPrivateKey());

        assertThat(new String(clearData, StandardCharsets.UTF_8)).isEqualTo(data);
    }

    @Test
    public void opensslDecJavaEnc() {
        CryptoOperations coKey = new CryptoBouncycastle();
        CryptoOperations coEnc = new CryptoBouncycastle();
        CryptoOperations coDec = new CryptoOpenssl();

        String data = "My Data";
        X500PrivateCredential kc = coKey.generateSelfSignedCred("signing");
        X500PrivateCredential req = coKey.generateRequestCred("req", kc);

        byte[] encData = coEnc.encryptCmsData(data.getBytes(StandardCharsets.UTF_8), req.getCertificate());
        byte[] clearData = coDec.decryptCmsData(encData, req.getPrivateKey());

        assertThat(new String(clearData, StandardCharsets.UTF_8)).isEqualTo(data);
    }
}
