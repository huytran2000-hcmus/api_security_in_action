package com.manning.apisecurityinaction.token;

import java.security.Key;
import java.util.Optional;

import software.pando.crypto.nacl.SecretBox;
import spark.Request;

public class EncryptedTokenStore implements TokenStore {
    private final Key encKey;
    private final TokenStore delegate;

    public EncryptedTokenStore(Key encKey, TokenStore delegate) {
        this.encKey = encKey;
        this.delegate = delegate;
    }

    @Override
    public String create(Request request, Token token) {
        var tokenId = delegate.create(request, token);
        return SecretBox.encrypt(encKey, tokenId).toString();
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        var decryptedToken = SecretBox.fromString(tokenId).decryptToString(encKey);
        return delegate.read(request, decryptedToken);
    }

    @Override
    public void revoke(Request request, String tokenId) {
        var decryptedToken = SecretBox.fromString(tokenId).decryptToString(encKey);
        delegate.revoke(request, decryptedToken);
    }
}
