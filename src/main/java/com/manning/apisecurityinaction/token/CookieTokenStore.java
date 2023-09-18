package com.manning.apisecurityinaction.token;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Optional;

import spark.Request;

public class CookieTokenStore implements TokenStore {
    public String create(Request request, Token token) {
        var session = request.session(false);
        if (session != null) {
            session.invalidate();
        }

        session = request.session(true);
        session.attribute("username", token.username);
        session.attribute("expiry", token.expiry);
        session.attribute("attributes", token.attributes);

        return Base64Url.encode(sha256(session.id()));
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        var session = request.session(false);
        if (session == null) {
            return Optional.empty();
        }
        var provided = Base64Url.decode(tokenId);
        var computed = sha256(session.id());
        if (!MessageDigest.isEqual(provided, computed)) {
            return Optional.empty();
        }
        String userId = session.attribute("username");
        Instant expiry = session.attribute("expiry");

        var token = new Token(userId, expiry);
        token.attributes.putAll(session.attribute("attributes"));

        return Optional.of(token);
    }

    public void revoke(Request request, String tokenId) {
        var session = request.session(false);
        if (session == null) {
            return;
        }

        var provided = Base64Url.decode(tokenId);
        var computed = sha256(session.id());
        if (!MessageDigest.isEqual(provided, computed)) {
            return;
        }
        session.invalidate();
    }

    static byte[] sha256(String tokenId) {
        try {
            var sha = MessageDigest.getInstance("SHA-256");
            return sha.digest(tokenId.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
