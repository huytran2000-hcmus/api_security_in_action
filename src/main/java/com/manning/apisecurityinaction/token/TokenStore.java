package com.manning.apisecurityinaction.token;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import spark.Request;

public interface TokenStore {
    String create(Request request, Token token);

    Optional<Token> read(Request request, String tokenId);

    void revoke(Request request, String tokenId);

    class Token {
        public final String username;
        public final Instant expiry;
        public final Map<String, String> attributes;

        public Token(String username, Instant expiry) {
            this.username = username;
            this.expiry = expiry;
            this.attributes = new ConcurrentHashMap<>();
        }
    }
}
