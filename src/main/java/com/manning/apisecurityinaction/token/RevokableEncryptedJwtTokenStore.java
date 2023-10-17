package com.manning.apisecurityinaction.token;

import java.text.ParseException;
import java.util.Date;
import java.util.Optional;
import java.util.Set;

import javax.crypto.SecretKey;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;

import spark.Request;

public class RevokableEncryptedJwtTokenStore implements SecureTokenStore {
    private final SecretKey encKey;
    private final String audience;
    private final DatabaseTokenStore allowlistStore;

    public RevokableEncryptedJwtTokenStore(SecretKey encKey,
            String audience,
            DatabaseTokenStore allowlistStore) {
        this.encKey = encKey;
        this.audience = audience;
        this.allowlistStore = allowlistStore;
    }

    @Override
    public String create(Request request, Token token) {
        var allowlistToken = new Token(token.username, token.expiry);
        var jwtId = allowlistStore.create(request, allowlistToken);
        var claimBuilder = new JWTClaimsSet.Builder()
                .subject(token.username)
                .audience(audience)
                .expirationTime(Date.from(token.expiry))
                .jwtID(jwtId);
        token.attributes.forEach(claimBuilder::claim);

        var header = new JWEHeader(JWEAlgorithm.DIR,
                EncryptionMethod.A128CBC_HS256);
        var jwt = new EncryptedJWT(header, claimBuilder.build());
        try {
            var encrypter = new DirectEncrypter(encKey);
            jwt.encrypt(encrypter);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return jwt.serialize();
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        try {
            var jwt = EncryptedJWT.parse(tokenId);

            var decrypter = new DirectDecrypter(encKey);
            jwt.decrypt(decrypter);

            var claims = jwt.getJWTClaimsSet();
            var jwtId = claims.getJWTID();
            if (allowlistStore.read(request, jwtId).isEmpty()) {
                return Optional.empty();
            }

            if (!claims.getAudience().contains(audience)) {
                return Optional.empty();
            }
            var expiry = claims.getExpirationTime().toInstant();
            var username = claims.getSubject();
            var token = new Token(username, expiry);
            var ignores = Set.of("sub", "exp", "aud");
            for (var attr : claims.getClaims().keySet()) {
                if (ignores.contains(attr)) {
                    continue;
                }
                token.attributes.put(attr, (String) claims.getClaim(attr));
            }

            return Optional.of(token);

        } catch (ParseException | JOSEException e) {
            return Optional.empty();
        }
    }

    @Override
    public void revoke(Request request, String tokenId) {
        try {
            var jwt = EncryptedJWT.parse(tokenId);
            var decrypter = new DirectDecrypter(encKey);
            jwt.decrypt(decrypter);

            var claims = jwt.getJWTClaimsSet();
            var jwtId = claims.getJWTID();
            allowlistStore.revoke(request, jwtId);
        } catch (ParseException | JOSEException e) {
            throw new IllegalArgumentException("invalid token; ", e);
        }
    }
}
