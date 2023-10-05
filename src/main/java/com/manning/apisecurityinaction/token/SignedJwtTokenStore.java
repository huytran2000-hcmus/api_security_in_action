package com.manning.apisecurityinaction.token;

import java.sql.Date;
import java.text.ParseException;
import java.util.Optional;
import java.util.Set;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import spark.Request;

public class SignedJwtTokenStore implements AuthenticatedTokenStore {
    private final JWSSigner singer;
    private final JWSAlgorithm algorithm;
    private final JWSVerifier verifier;
    private final String audience;

    public SignedJwtTokenStore(JWSSigner signer, JWSAlgorithm algorithm, JWSVerifier verifier, String audience) {
        this.singer = signer;
        this.algorithm = algorithm;
        this.verifier = verifier;
        this.audience = audience;
    }

    @Override
    public String create(Request request, Token token) {
        var claimBuilder = new JWTClaimsSet.Builder()
                .subject(token.username)
                .audience(audience)
                .expirationTime(Date.from(token.expiry));
        token.attributes.forEach(claimBuilder::claim);

        var header = new JWSHeader(algorithm);
        var jwt = new SignedJWT(header, claimBuilder.build());
        try {
            jwt.sign(singer);
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        try {
            var jwt = SignedJWT.parse(tokenId);
            if (!jwt.verify(verifier)) {
                throw new JOSEException("Invalid signature");
            }

            var claims = jwt.getJWTClaimsSet();
            if (!claims.getAudience().contains(audience)) {
                throw new JOSEException("Invalid audience");
            }
            var userId = claims.getSubject();
            var expiry = claims.getExpirationTime().toInstant();
            var token = new Token(userId, expiry);
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
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'revoke'");
    }
}
