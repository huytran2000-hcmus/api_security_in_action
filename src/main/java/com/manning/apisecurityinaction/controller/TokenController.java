package com.manning.apisecurityinaction.controller;

import static java.time.Instant.now;

import java.time.temporal.ChronoUnit;

import org.json.JSONObject;

import com.manning.apisecurityinaction.token.TokenStore;

import spark.Request;
import spark.Response;

public class TokenController {
    private final TokenStore store;

    public TokenController(TokenStore store) {
        this.store = store;
    }

    public JSONObject login(Request request, Response response) {
        String user_id = request.attribute(UserController.USERNAME_ATTR_KEY);

        var expiry = now().plus(10, ChronoUnit.MINUTES);
        var token = new TokenStore.Token(user_id, expiry);
        var tokenId = store.create(request, token);
        response.status(200);
        return new JSONObject().put("token", tokenId);
    }

    public void validateToken(Request request, Response response) {
        var authHeader = request.headers("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }
        var tokenId = authHeader.substring(7);
        store.read(request, tokenId).ifPresent(token -> {
            if (!now().isBefore(token.expiry)) {
                response.header("WWW-Authenticate",
                        "Bearer error=\"invalid_token\" \"error_description=\"Expired\"");
                return;
            }
            request.attribute(UserController.USERNAME_ATTR_KEY, token.username);
            request.attribute(UserController.ATTRS_ATTR_KEY, token.attributes);
            token.attributes.forEach(request::attribute);
        });
    }

    public JSONObject logout(Request request, Response response) {
        var authHeader = request.headers("Authorization");
        if (authHeader == null || authHeader.startsWith("Bearer ")) {
            throw new IllegalArgumentException("missing token header");
        }

        var tokenId = authHeader.substring(7);
        store.revoke(request, tokenId);
        response.status(200);
        return new JSONObject();
    }
}
