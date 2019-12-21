package rs.ac.uns.ftn.sep.commons.jwtsecurity;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.web.server.Ssl;
import org.springframework.stereotype.Component;
import org.springframework.util.ResourceUtils;

import javax.annotation.PostConstruct;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

@RequiredArgsConstructor
@Component
public class JwtKeys {
    private final ServerProperties serverProperties;
    private final JwtProperties jwtProperties;

    private PrivateKey privateKey;
    private PublicKey publicKey;

    @PostConstruct
    public void loadKeys() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        try {
            privateKey = loadPrivateKey();
            publicKey = loadPublicKeyFromKeystore();
        } catch (Exception ignored) {
            publicKey = loadPublicKeyFromTruststore();
        }
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    private PrivateKey loadPrivateKey() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        Ssl ssl = serverProperties.getSsl();
        KeyStore keyStore = KeyStore.getInstance(ssl.getKeyStoreType());
        keyStore.load(new FileInputStream(ResourceUtils.getFile(ssl.getKeyStore())), ssl.getKeyStorePassword().toCharArray());

        String password = ssl.getKeyPassword();
        char[] passwordCharArray = password != null ? password.toCharArray() : null;

        return (PrivateKey) keyStore.getKey(ssl.getKeyAlias(), passwordCharArray);
    }

    private PublicKey loadPublicKeyFromKeystore() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        Ssl ssl = serverProperties.getSsl();
        return loadPublicKey(ssl.getKeyStoreType(), ssl.getKeyStore(), ssl.getKeyAlias(), ssl.getKeyStorePassword());
    }

    private PublicKey loadPublicKeyFromTruststore() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        Ssl ssl = serverProperties.getSsl();
        return loadPublicKey(ssl.getTrustStoreType(), ssl.getTrustStore(), jwtProperties.getSigningKey(), ssl.getTrustStorePassword());
    }

    private PublicKey loadPublicKey(String storeType, String store, String alias, String storePassword) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance(storeType);
        keyStore.load(new FileInputStream(ResourceUtils.getFile(store)), passwordToCharArray(storePassword));

        Certificate authenticator = keyStore.getCertificate(alias);
        return authenticator.getPublicKey();
    }

    private char[] passwordToCharArray(String password) {
        return password != null ? password.toCharArray() : null;
    }

}
