package ch.avcommits.securetransportation;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;

import javax.security.auth.x500.X500PrivateCredential;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

@Slf4j
@Component
public class CryptoOpenssl implements CryptoOperations {
    @Override
    public X500PrivateCredential generateSelfSignedCred(String certName) {
        throw new RuntimeException("not implemented");
    }

    @Override
    public X500PrivateCredential generateRequestCred(String certName, X500PrivateCredential caCred) {
        throw new RuntimeException("not implemented");
    }

    @Override
    public byte[] encryptCmsData(byte[] data, X509Certificate encryptionCertificate) {
        byte[] result;

        File certFile = null;
        File contentFile = null;
        File encryptedFile = null;
        //"openssl cms -encrypt -outform PEM -aes-128-cbc -in json_content.txt -out json_content_cc.enc -recip mobile_rsa_encdec.pem.crt -keyopt rsa_padding_mode:oaep rsa_oaep_md:sha256"
        try {
            certFile = File.createTempFile("reqcert", ".crt");
            contentFile = File.createTempFile("content", ".txt");
            encryptedFile = File.createTempFile("content", ".enc");
            FileUtils.write(certFile, CertUtils.formatCrtFileContents(encryptionCertificate),
                    StandardCharsets.UTF_8);
            FileUtils.writeByteArrayToFile(contentFile, data);

            log.info("Cert file created {}", certFile.getAbsolutePath());
            log.info("Content file created {}", contentFile.getAbsolutePath());
            log.info("Encrypted file created {}", encryptedFile.getAbsolutePath());

            String cmdParam = "cms -encrypt -outform PEM -aes-128-cbc" +
                    " -in \"" + contentFile.getAbsolutePath() + "\"" +
                    " -out \"" + encryptedFile.getAbsolutePath() + "\"" +
                    " -recip \"" + certFile.getAbsolutePath() + "\"" +
                    " -keyopt rsa_padding_mode:oaep -keyopt rsa_oaep_md:sha256";

            //openssl should be in path
            Runtime rt = Runtime.getRuntime();
            final String cmd = "\"C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe\" " + cmdParam;
            Process proc = rt.exec(cmd);

            final String stdInputS = StreamUtils.copyToString(proc.getInputStream(), StandardCharsets.UTF_8);
            final String stdErrorS = StreamUtils.copyToString(proc.getErrorStream(), StandardCharsets.UTF_8);

            log.info("stdin: {}", stdInputS);
            log.info("stderr: {}", stdErrorS);

            if (proc.exitValue() != 0) {
                log.error("stdin: {}", stdInputS);
                log.error("stderr: {}", stdErrorS);
                throw new RuntimeException("Command failed");
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            List<String> lines = FileUtils.readLines(encryptedFile, StandardCharsets.UTF_8);
            for (String line : lines) {
                if (!line.startsWith("---"))
                    baos.write(line.getBytes(StandardCharsets.UTF_8));
            }

            result = Base64.decode(baos.toByteArray());
            log.info("Content parsed");
        } catch (IOException e) {
            throw new RuntimeException(e);
        } finally {
            FileUtils.deleteQuietly(certFile);
            FileUtils.deleteQuietly(encryptedFile);
            FileUtils.deleteQuietly(contentFile);
        }
        return result;
    }

    @Override
    public byte[] decryptCmsData(byte[] encryptedData, PrivateKey decryptionKey) {
        byte[] result;

        File keyFile = null;
        File contentFile = null;
        File encryptedFile = null;

        try {
            keyFile = File.createTempFile("reqkey", ".key");
            contentFile = File.createTempFile("content", ".txt");
            encryptedFile = File.createTempFile("content", ".enc");
            FileUtils.write(keyFile, CertUtils.formatKeyFileContents(decryptionKey),
                    StandardCharsets.UTF_8);
            FileUtils.write(encryptedFile, CertUtils.formatCmsFileContents(encryptedData),
                    StandardCharsets.UTF_8);

            log.info("Key file created {}", keyFile.getAbsolutePath());
            log.info("Content file created {}", contentFile.getAbsolutePath());
            log.info("Encrypted file created {}", encryptedFile.getAbsolutePath());

            String cmdParam = "cms -decrypt -inform PEM" +
                    " -in \"" + encryptedFile.getAbsolutePath() + "\"" +
                    " -inkey \"" + keyFile.getAbsolutePath() + "\"" +
                    " -out \"" + contentFile.getAbsolutePath() + "\"" +
                    " -keyopt rsa_padding_mode:oaep -keyopt rsa_oaep_md:sha256";

            //openssl should be in path
            Runtime rt = Runtime.getRuntime();
            final String cmd = "\"C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe\" " + cmdParam;
            Process proc = rt.exec(cmd);

            log.info("cmd: {}", cmdParam);

            final String stdInputS = StreamUtils.copyToString(proc.getInputStream(), StandardCharsets.UTF_8);
            final String stdErrorS = StreamUtils.copyToString(proc.getErrorStream(), StandardCharsets.UTF_8);

            log.info("stdin: {}", stdInputS);
            log.info("stderr: {}", stdErrorS);

            if (proc.exitValue() != 0) {
                log.error("stdin: {}", stdInputS);
                log.error("stderr: {}", stdErrorS);
                throw new RuntimeException("Command failed");
            }

            result = FileUtils.readFileToByteArray(contentFile);
            log.info("Content parsed");
        } catch (IOException e) {
            throw new RuntimeException(e);
        } finally {
            FileUtils.deleteQuietly(keyFile);
            FileUtils.deleteQuietly(encryptedFile);
            FileUtils.deleteQuietly(contentFile);
        }
        return result;
    }
}
