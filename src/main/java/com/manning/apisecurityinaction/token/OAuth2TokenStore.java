package com.manning.apisecurityinaction.token;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

import org.json.JSONObject;

import com.manning.apisecurityinaction.controller.UserController;

import spark.Request;

public class OAuth2TokenStore implements SecureTokenStore {
    private final URI introspectionUri;
    private final URI revocationUri;
    private final String authorization;
    private final HttpClient client;

    public OAuth2TokenStore(URI introspectionUri, URI revocationUri, String clientId, String clientSecret) {
        this.introspectionUri = introspectionUri;
        this.revocationUri = revocationUri;
        var credentials = URLEncoder.encode(clientId, UTF_8) + ":" +
                URLEncoder.encode(clientSecret, UTF_8);
        this.authorization = "Basic " + Base64.getEncoder()
                .encodeToString(credentials.getBytes(UTF_8));

        var sslParams = new SSLParameters();
        sslParams.setProtocols(new String[] { "TLSv1.3", "TLSv1.2" });
        sslParams.setCipherSuites(new String[] {
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        });
        sslParams.setUseCipherSuitesOrder(true);
        sslParams.setEndpointIdentificationAlgorithm("HTTPS");

        try {
            var trustedCerts = KeyStore.getInstance("PKCS12");
            trustedCerts.load(new FileInputStream("as.example.com.ca.p12"), "change-it".toCharArray());
            var tmf = TrustManagerFactory.getInstance("PKIX");
            tmf.init(trustedCerts);
            var sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);

            this.client = HttpClient.newBuilder()
                    .sslParameters(sslParams)
                    .sslContext(sslContext)
                    .build();
        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String create(Request request, Token token) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'create'");
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        if (!isValidToken(tokenId)) {
            return Optional.empty();
        }

        var form = "token=" + URLEncoder.encode(tokenId, UTF_8) + "&token_type_hint=access_token";
        var httpRequest = HttpRequest.newBuilder()
                .uri(introspectionUri)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Authorization", authorization)
                .POST(BodyPublishers.ofString(form))
                .build();

        try {
            var httpResponse = client.send(httpRequest, BodyHandlers.ofString());
            if (httpResponse.statusCode() == 200) {
                var json = new JSONObject(httpResponse.body());
                if (json.getBoolean("active")) {
                    return processResponse(json, request);
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }

        return Optional.empty();
    }

    private Optional<Token> processResponse(JSONObject jsonRes, Request request) {
        var expiry = Instant.ofEpochSecond(jsonRes.getLong("exp"));
        var subject = jsonRes.getString("sub");

        var confirmationKey = jsonRes.optJSONObject("cnf");
        if (confirmationKey != null) {
            for (var method : confirmationKey.keySet()) {
                if (!"x5#S256".equals(method)) {
                    throw new RuntimeException("Unknown confirmation method: " + method);
                }

                if (!"SUCCESS".equals(request.headers("ssl-client-verify"))) {
                    return Optional.empty();
                }

                var expectedHash = Base64Url.decode(confirmationKey.getString(method));
                var cert = UserController.decodeCert(request.headers("ssl-client-cert"));
                var certHash = thumbprint(cert);

                if (!MessageDigest.isEqual(expectedHash, certHash)) {
                    return Optional.empty();
                }
            }
        }
        var token = new Token(subject, expiry);
        token.attributes.put("scope", jsonRes.getString("scope"));
        token.attributes.put("client_id", jsonRes.optString("client_id"));

        return Optional.of(token);
    }

    @Override
    public void revoke(Request request, String tokenId) {
        if (!isValidToken(tokenId)) {
            return;
        }

        var form = "token=" + URLEncoder.encode(tokenId, UTF_8) +
                "&token_type_hint=access_token";

        var httpRequest = HttpRequest.newBuilder()
                .uri(revocationUri)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Authorization", authorization)
                .POST(BodyPublishers.ofString(form))
                .build();

        try {
            client.send(httpRequest, BodyHandlers.discarding());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] thumbprint(X509Certificate certificate) {
        try {
            var sha256 = MessageDigest.getInstance("SHA-256");
            return sha256.digest(certificate.getEncoded());
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public boolean isValidToken(String tokenId) {
        return tokenId.matches("[\\x20-\\x7E]{1,1024}");
    }
}
