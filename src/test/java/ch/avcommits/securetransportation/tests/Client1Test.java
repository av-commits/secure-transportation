package ch.avcommits.securetransportation.tests;

import ch.avcommits.securetransportation.*;
import com.google.gson.Gson;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.server.LocalServerPort;

import javax.security.auth.x500.X500PrivateCredential;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class Client1Test {
    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private CryptoOperations crypto;

    @Test
    public void greetingShouldReturnDefaultMessage() {
        String baseUrl = "http://localhost:" + port + "/";

        X500PrivateCredential caCred = crypto.generateSelfSignedCred("signing");
        String caBase64 = CertUtils.toBase64(caCred.getCertificate());

        X500PrivateCredential requestCert = crypto.generateRequestCred("myRequest", caCred);
        String requestBase64 = CertUtils.toBase64(requestCert.getCertificate());

        CaEntity ca = new CaEntity();
        ca.setCaContent(caBase64);
        restTemplate.put(baseUrl + "ca/testCa", ca);

        CardCredentialRequest ccr = new CardCredentialRequest();
        ccr.setResponsePublicKey(requestBase64);

        CardCredential cc = restTemplate.postForObject(baseUrl + "cards/12345/credentialsPan",
                ccr, CardCredential.class);

        byte[] dedata = crypto.decryptCmsData(Base64.getDecoder().decode(cc.getEncryptedContent()),
                requestCert.getPrivateKey());
        Gson gson = new Gson();
        CardCredentialDetail ccd = gson.fromJson(new String(dedata, StandardCharsets.UTF_8),
                CardCredentialDetail.class);

        log.info("Content: {}", new String(dedata, StandardCharsets.UTF_8));
        log.info("CardID: {}", ccd.getCardID());
        log.info("PAN: {}", ccd.getPan());
        log.info("Valid To: {}", ccd.getValidTo());
        log.info("Embosser Name: {}", ccd.getEmbosserName());


        String pan2 = TripleDes.decrypt(Base64.getDecoder().decode(ccd.getEncryptedPan())
                , "Secret12".getBytes(StandardCharsets.UTF_8));
        log.info("PAN ENC: {}", pan2);

        assertThat(pan2).isEqualTo(ccd.getPan());
    }
}
