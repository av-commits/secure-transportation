package ch.avcommits.securetransportation;

import java.io.ByteArrayInputStream;
import java.security.PrivateKey;
import java.security.cert.*;
import java.util.Base64;

public class CertUtils {
    public static X509Certificate loadCertificate(String base64) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(Base64
                            .getDecoder().decode(base64)));
        } catch (CertificateException e) {
            throw new RuntimeException();
        }
    }

    public static String toBase64(X509Certificate cert) {
        try {
            return Base64.getEncoder().encodeToString(cert.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public static String formatCrtFileContents(final Certificate certificate)  {
        final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
        final String END_CERT = "-----END CERTIFICATE-----";
        final String LINE_SEPARATOR = System.getProperty("line.separator");

        final Base64.Encoder encoder = Base64.getMimeEncoder(64, LINE_SEPARATOR.getBytes());

        byte[] rawCrtText = null;
        try {
            rawCrtText = certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
        final String encodedText = new String(encoder.encode(rawCrtText));
        final String prettified = BEGIN_CERT + LINE_SEPARATOR + encodedText + LINE_SEPARATOR + END_CERT;
        return prettified;
    }

    public static String formatKeyFileContents(final PrivateKey key)  {
        final String BEGIN_KEY = "-----BEGIN RSA PRIVATE KEY-----";
        final String END_KEY = "-----END RSA PRIVATE KEY-----";
        final String LINE_SEPARATOR = System.getProperty("line.separator");

        final Base64.Encoder encoder = Base64.getMimeEncoder(64, LINE_SEPARATOR.getBytes());

        byte[] rawCrtText = key.getEncoded();

        final String encodedText = new String(encoder.encode(rawCrtText));
        final String prettified = BEGIN_KEY + LINE_SEPARATOR + encodedText + LINE_SEPARATOR + END_KEY;
        return prettified;
    }

    public static String formatCmsFileContents(final byte[] content)  {
        final String BEGIN_KEY = "-----BEGIN CMS-----";
        final String END_KEY = "-----END CMS-----";
        final String LINE_SEPARATOR = System.getProperty("line.separator");

        final Base64.Encoder encoder = Base64.getMimeEncoder(64, LINE_SEPARATOR.getBytes());

        final String encodedText = new String(encoder.encode(content));
        final String prettified = BEGIN_KEY + LINE_SEPARATOR + encodedText + LINE_SEPARATOR + END_KEY;
        return prettified;
    }
}
