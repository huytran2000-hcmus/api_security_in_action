package com.manning.apisecurityinaction.controller;

import static java.time.Instant.now;
import static spark.Spark.halt;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

import org.json.JSONObject;

import com.manning.apisecurityinaction.controller.UserController.Permission;
import com.manning.apisecurityinaction.token.SecureTokenStore;
import com.manning.apisecurityinaction.token.TokenStore.Token;

import spark.Request;
import spark.Response;

public class CapabilityController {
    private final SecureTokenStore tokenStore;

    public CapabilityController(SecureTokenStore tokenStore) {
        this.tokenStore = tokenStore;
    }

    public URI createUri(Request request, String path, Permission perms, Duration expiryDuration) {
        var token = new Token(null, now().plus(expiryDuration));
        token.attributes.put("path", path);
        token.attributes.put("perms", perms.toString());

        var tokenId = tokenStore.create(request, token);

        var uri = URI.create(request.uri());
        return uri.resolve(path + "?access_token=" + tokenId);
    }

    public void lookupPermissions(Request request, Response response) {
        var tokenId = request.queryParams("access_token");
        if (tokenId == null) {
            return;
        }

        tokenStore.read(request, tokenId).ifPresent(token -> {
            if (!now().isBefore(token.expiry)) {
                return;
            }

            var tokenPath = token.attributes.get("path");
            if (Objects.equals(tokenPath, request.pathInfo())) {
                Permission currentPerms = request.attribute(UserController.PERMS_ATTR_KEY);
                Permission extraPermission = Permission.fromString(token.attributes.get("perms"));
                request.attribute(UserController.PERMS_ATTR_KEY, currentPerms.combine(extraPermission));
            }
        });
    }

    public JSONObject share(Request request, Response response) {
        var json = new JSONObject(request.body());

        var capURI = URI.create(json.getString("uri"));
        var query = capURI.getQuery();
        var tokenId = query.substring(query.indexOf("=") + 1);

        var token = tokenStore.read(request, tokenId)
                .orElseThrow(() -> new IllegalArgumentException("token not found"));

        Instant expiry = Instant.parse(json.getString("expiry"));
        if (expiry.isAfter(token.expiry)) {
            throw new IllegalArgumentException("expiry pass the expiry of token");
        }

        var path = capURI.getPath();
        if (!path.equals(token.attributes.get("path"))) {
            throw new IllegalArgumentException("incorrect path");
        }

        var perms = Permission.fromString(token.attributes.get(UserController.PERMS_ATTR_KEY));
        var requestPerms = Permission.fromString(json.getString(UserController.PERMS_ATTR_KEY));
        if (!perms.satisfies(requestPerms)) {
            halt(403);
        }

        var user = json.getString("username");
        var newToken = new Token(user, expiry);
        newToken.attributes.put("path", path);
        newToken.attributes.put(UserController.PERMS_ATTR_KEY, requestPerms.toString());
        var newTokenId = tokenStore.create(request, newToken);

        var uri = URI.create(request.uri());
        var newCapUri = uri.resolve(path + "?access_token=" + newTokenId);
        return new JSONObject().put("uri", newCapUri);
    }

}
