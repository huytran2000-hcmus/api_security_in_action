package com.manning.apisecurityinaction.controller;

import static java.time.Instant.now;
import static spark.Spark.halt;

import java.time.temporal.ChronoUnit;

import org.json.JSONObject;

import com.manning.apisecurityinaction.token.SecureTokenStore;
import com.manning.apisecurityinaction.token.TokenStore;

import spark.Request;
import spark.Response;

public class TokenController {
    private static final String DEFAULT_SCOPES = "create_space read_space post_message read_message list_message " +
            "delete_message add_member";
    private final SecureTokenStore store;

    public TokenController(SecureTokenStore store) {
        this.store = store;
    }

    public JSONObject login(Request request, Response response) {
        String user_id = request.attribute(UserController.USERNAME_ATTR_KEY);
        var expiry = now().plus(10, ChronoUnit.MINUTES);
        var token = new TokenStore.Token(user_id, expiry);
        var scope = request.queryParamOrDefault("scope", DEFAULT_SCOPES);
        token.attributes.put("scope", scope);

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
                halt(401);
                return;
            }
            request.attribute(UserController.USERNAME_ATTR_KEY, token.username);
            token.attributes.forEach(request::attribute);
        });
    }

    public JSONObject logout(Request request, Response response) {
        var authHeader = request.headers("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new IllegalArgumentException("missing token header");
        }

        var tokenId = authHeader.substring(7);
        store.revoke(request, tokenId);
        response.status(200);
        return new JSONObject();
    }
}
