package com.manning.apisecurityinaction.token;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Optional;

import org.json.JSONException;
import org.json.JSONObject;

import spark.Request;

public class JsonTokenStore implements TokenStore {
    @Override
    public String create(Request request, Token tokenId) {
        var json = new JSONObject();
        json.put("sub", tokenId.username);
        json.put("exp", tokenId.expiry.getEpochSecond());
        json.put("attrs", tokenId.attributes);

        var jsonBytes = json.toString().getBytes(StandardCharsets.UTF_8);

        return Base64Url.encode(jsonBytes);
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        try {
            var jsonBytes = Base64Url.decode(tokenId);
            var json = new JSONObject(new String(jsonBytes, StandardCharsets.UTF_8));
            var username = json.getString("sub");
            var expiry = Instant.ofEpochSecond(json.getInt("exp"));
            var attrs = json.getJSONObject("attrs");

            var token = new Token(username, expiry);
            for (var key : attrs.keySet()) {
                token.attributes.put(key, tokenId);
            }

            return Optional.of(token);
        } catch (JSONException ex) {
            return Optional.empty();
        }
    }

    @Override
    public void revoke(Request request, String tokenId) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'revoke'");
    }
}