package ch.avcommits.securetransportation;

import com.google.gson.Gson;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Base64;

@RestController
@RequestMapping("/cards")
@Slf4j
public class CardRestController {
    @Autowired
    private TrustedCaStore caStore;

    @Autowired
    private CryptoOperations crypto;

    @PostMapping("{cardID}/credentials2")
    CardCredential getCardCreds(@RequestBody CardCredentialRequest req, @PathVariable String cardID) {
        log.info("Get Card Credentials for {}", cardID);
        X509Certificate pk = CertUtils.loadCertificate(req.getResponsePublicKey());

        caStore.validateCert(pk);

        CardCredentialDetail ccd = new CardCredentialDetail();
        ccd.setCardID(cardID);
        ccd.setPan("5422442132122333");
        ccd.setValidTo( "2023-08-31");
        ccd.setEmbosserName("Hans Muster");
        ccd.setEncryptedPan(Base64.getEncoder().encodeToString(
                TripleDes.encrypt(ccd.getPan(), "Secret12".getBytes(StandardCharsets.UTF_8))));

        Gson gson = new Gson();
        byte[] eData = crypto.encryptCmsData(gson.toJson(ccd).getBytes(StandardCharsets.UTF_8), pk);
        log.info("Data to encrypt: {}", gson.toJson(ccd));

        CardCredential cc = new CardCredential();
        cc.setCardId(cardID);
        cc.setEncryptedContent(Base64.getEncoder().encodeToString(eData));

        return cc;
    }
}
