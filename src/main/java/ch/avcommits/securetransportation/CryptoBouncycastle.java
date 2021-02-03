package ch.avcommits.securetransportation;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import javax.security.auth.x500.X500PrivateCredential;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Collection;
import java.util.Date;

@Slf4j
@Component
@Primary
public class CryptoBouncycastle implements CryptoOperations {
    private KeyPair generateRSAKeyPair() {
        try {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
            kpGen.initialize(2048, new SecureRandom());
            return kpGen.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    public X500PrivateCredential generateSelfSignedCred(String certName) {
        X500Name name = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, certName)
                .build();

        try {
            KeyPair kp = generateRSAKeyPair();

            final SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
            final LocalDate sd = LocalDate.now();
            final LocalDate ed = sd.plusYears(2);

            final X509v3CertificateBuilder builder = new X509v3CertificateBuilder(name,
                    BigInteger.valueOf(new SecureRandom().nextLong()),
                    Date.from(sd.atStartOfDay().atZone(ZoneId.systemDefault()).toInstant()),
                    Date.from(ed.atStartOfDay().atZone(ZoneId.systemDefault()).toInstant()),
                    name,
                    subPubKeyInfo
            );
            builder.addExtension(
                    new ASN1ObjectIdentifier("2.5.29.15"),
                    true,
                    new X509KeyUsage(X509KeyUsage.keyCertSign));
            builder.addExtension(
                    new ASN1ObjectIdentifier("2.5.29.19"),
                    false,
                    new BasicConstraints(true)); // true if it is allowed to sign other certs

            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
                    .setProvider(new BouncyCastleProvider()).build(kp.getPrivate());
            final X509CertificateHolder holder = builder.build(signer);

            X509Certificate cert = new JcaX509CertificateConverter()
                    .setProvider(new BouncyCastleProvider()).getCertificate(holder);

            return new X500PrivateCredential(cert, kp.getPrivate(), certName);
        } catch (OperatorCreationException | CertificateException | CertIOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public X500PrivateCredential generateRequestCred(String certName, X500PrivateCredential caCred) {
        X500Name name = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, certName)
                .build();

        try {
            KeyPair kp = generateRSAKeyPair();

            final X500Name caSubject = X500Name.getInstance(ASN1Primitive.fromByteArray(caCred.getCertificate().getSubjectX500Principal().getEncoded()));

            final SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
            final LocalDate sd = LocalDate.now();
            final LocalDate ed = sd.plusDays(1);

            final X509v3CertificateBuilder builder = new X509v3CertificateBuilder(caSubject,
                    BigInteger.valueOf(new SecureRandom().nextLong()),
                    Date.from(sd.atStartOfDay().atZone(ZoneId.systemDefault()).toInstant()),
                    Date.from(ed.atStartOfDay().atZone(ZoneId.systemDefault()).toInstant()),
                    name,
                    subPubKeyInfo
            );
            builder.addExtension(
                    new ASN1ObjectIdentifier("2.5.29.15"),
                    true,
                    new X509KeyUsage(X509KeyUsage.dataEncipherment));
            builder.addExtension(
                    new ASN1ObjectIdentifier("2.5.29.19"),
                    false,
                    new BasicConstraints(false)); // true if it is allowed to sign other certs

            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
                    .setProvider(new BouncyCastleProvider()).build(caCred.getPrivateKey());
            final X509CertificateHolder holder = builder.build(signer);

            X509Certificate cert = new JcaX509CertificateConverter()
                    .setProvider(new BouncyCastleProvider()).getCertificate(holder);

            return new X500PrivateCredential(cert, kp.getPrivate(), certName);
        } catch (OperatorCreationException | CertificateException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] encryptCmsData(byte[] data, X509Certificate encryptionCertificate) {
        if (null == data && null == encryptionCertificate)
            throw new NullPointerException();

        try {
            CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator
                    = new CMSEnvelopedDataGenerator();


            JceKeyTransRecipientInfoGenerator jceKey
                    = new JceKeyTransRecipientInfoGenerator(encryptionCertificate);
            //jceKey.setAlgorithmMapping(PKCSObjectIdentifiers.rsaEncryption, "RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cmsEnvelopedDataGenerator.addRecipientInfoGenerator(jceKey);
            CMSTypedData msg = new CMSProcessableByteArray(data);

            OutputEncryptor encryptor
                    = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC)
                    .setProvider("BC").build();
            CMSEnvelopedData cmsEnvelopedData = cmsEnvelopedDataGenerator
                    .generate(msg, encryptor);
            return cmsEnvelopedData.getEncoded();
        } catch (IOException | CMSException | CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] decryptCmsData(byte[] encryptedData, PrivateKey decryptionKey) {
        if (null == encryptedData || null == decryptionKey)
            throw new NullPointerException();

        try {
            CMSEnvelopedData envelopedData = new CMSEnvelopedData(encryptedData);

            Collection<RecipientInformation> recipients
                    = envelopedData.getRecipientInfos().getRecipients();
            KeyTransRecipientInformation recipientInfo
                    = (KeyTransRecipientInformation) recipients.iterator().next();
            JceKeyTransRecipient recipient
                    = new JceKeyTransEnvelopedRecipient(decryptionKey);
            //recipient.setAlgorithmMapping(PKCSObjectIdentifiers.rsaEncryption, "RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

            return recipientInfo.getContent(recipient);
        } catch (CMSException e) {
            throw new RuntimeException(e);
        }
    }
}
