package ch.avcommits.securetransportation;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayInputStream;
import java.security.cert.*;
import java.util.Base64;

@RestController
@RequestMapping("/ca")
public class CARestController {
    private final TrustedCaStore caStore;

    @Autowired
    public CARestController(TrustedCaStore caStore) {
        this.caStore = caStore;
    }

    @PutMapping("/{name}")
    void addCa(@RequestBody CaEntity ca, @PathVariable String name) {
        byte [] decoded = Base64.getDecoder().decode(ca.getCaContent());
        try {
            caStore.addCa(name, (X509Certificate) CertificateFactory
                    .getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(decoded)));
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }
}
