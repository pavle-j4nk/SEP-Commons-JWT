package rs.ac.uns.ftn.sep.commons.jwtsecurity;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import rs.ac.uns.ftn.sep.commons.ssl.SslKeys;

import javax.annotation.PostConstruct;
import java.security.*;
import java.security.cert.Certificate;

@RequiredArgsConstructor
@Component
public class JwtKeys {
    private final SslKeys sslKeys;
    private final JwtProperties jwtProperties;

    private PrivateKey privateKey;
    private PublicKey publicKey;

    @PostConstruct
    public void loadKeys() throws Exception {
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

    private PrivateKey loadPrivateKey() throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore keyStore = sslKeys.getKeyStore();

        String password = jwtProperties.getSigningKeyPassword();
        char[] passwordCharArray = password != null ? password.toCharArray() : null;

        return (PrivateKey) keyStore.getKey(jwtProperties.getSigningKey(), passwordCharArray);
    }

    private PublicKey loadPublicKeyFromKeystore() throws KeyStoreException {
        KeyStore keyStore = sslKeys.getKeyStore();
        return loadPublicKey(keyStore, jwtProperties.getSigningKey());
    }

    private PublicKey loadPublicKeyFromTruststore() throws Exception {
        KeyStore trustStore = sslKeys.getTrustStore();
        return loadPublicKey(trustStore, jwtProperties.getSigningKey());
    }

    private PublicKey loadPublicKey(KeyStore keyStore, String alias) throws KeyStoreException {
        Certificate authenticator = keyStore.getCertificate(alias);
        return authenticator.getPublicKey();
    }

}
