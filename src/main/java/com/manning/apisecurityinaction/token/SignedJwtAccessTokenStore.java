package com.manning.apisecurityinaction.token;

import java.text.ParseException;
import java.util.Optional;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import spark.Request;

public class SignedJwtAccessTokenStore implements SecureTokenStore {
    private final String issuer;
    private final String audience;
    private final JWSAlgorithm algorithm;
    private final JWKSource<SecurityContext> jwkSource;

    public SignedJwtAccessTokenStore(String issuer, String audience, JWSAlgorithm algorithm,
            JWKSource<SecurityContext> jwkSource) {
        this.issuer = issuer;
        this.audience = audience;
        this.algorithm = algorithm;
        this.jwkSource = jwkSource;
    }

    @Override
    public String create(Request request, Token token) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'create'");
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        try {
            var verifier = new DefaultJWTProcessor<>();
            var keySelector = new JWSVerificationKeySelector<>(algorithm, jwkSource);
            verifier.setJWSKeySelector(keySelector);

            var claims = verifier.process(tokenId, null);
            if (!issuer.equals(claims.getIssuer())) {
                return Optional.empty();
            }

            if (claims.getAudience().contains(audience)) {
                return Optional.empty();
            }

            var expiry = claims.getExpirationTime().toInstant();
            var sub = claims.getSubject();
            var token = new Token(sub, expiry);

            String scope;
            try {
                scope = claims.getStringClaim("scope");

            } catch (ParseException e) {
                scope = String.join(" ", claims.getStringListClaim("scope"));
            }
            token.attributes.put("scope", scope);
            return Optional.of(token);
        } catch (ParseException | BadJOSEException | JOSEException e) {
            return Optional.empty();
        }
    }

    @Override
    public void revoke(Request request, String tokenId) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'revoke'");
    }
}
