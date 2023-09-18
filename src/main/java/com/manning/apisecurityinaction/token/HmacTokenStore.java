package com.manning.apisecurityinaction.token;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.util.Optional;

import javax.crypto.Mac;

import spark.Request;

public class HmacTokenStore implements TokenStore {
    private final TokenStore delegate;
    private final Key macKey;

    public HmacTokenStore(TokenStore store, Key key) {
        this.delegate = store;
        this.macKey = key;
    }

    @Override
    public String create(Request request, Token token) {
        var tokenId = delegate.create(request, token);
        var tag = hmac(tokenId);

        return tokenId + "." + Base64Url.encode(tag);
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        var realToken = validateAndReadTag(tokenId);
        if (realToken == "") {
            return Optional.empty();
        }

        return delegate.read(request, realToken);
    }

    @Override
    public void revoke(Request request, String tokenId) {
        var realToken = validateAndReadTag(tokenId);
        if (realToken == "") {
            return;
        }

        delegate.revoke(request, realToken);
    }

    private String validateAndReadTag(String tokenId) {
        var index = tokenId.lastIndexOf(".");
        if (index == -1) {
            return "";
        }
        var realToken = tokenId.substring(0, index);
        var provided = Base64Url.decode(tokenId.substring(index + 1));
        var computed = hmac(realToken);
        if (!MessageDigest.isEqual(provided, computed)) {
            return "";
        }
        return realToken;
    }

    private byte[] hmac(String tokenId) {
        try {
            var mac = Mac.getInstance(macKey.getAlgorithm());
            mac.init(macKey);

            return mac.doFinal(tokenId.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }
}
