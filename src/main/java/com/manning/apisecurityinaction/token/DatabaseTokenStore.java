package com.manning.apisecurityinaction.token;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.dalesbred.Database;
import org.json.JSONObject;

import spark.Request;

public class DatabaseTokenStore implements SecureTokenStore {
    private final Database database;
    private final SecureRandom rand;

    public DatabaseTokenStore(Database database) {
        this.database = database;
        this.rand = new SecureRandom();

        Executors.newSingleThreadScheduledExecutor()
                .scheduleAtFixedRate(this::deleteExpiredToken, 10, 10, TimeUnit.MINUTES);
    }

    private String randomId() {
        var data = new byte[20];
        rand.nextBytes(data);
        return Base64Url.encode(data);
    }

    @Override
    public String create(Request request, Token token) {
        var tokenId = randomId();
        var hashedTokenId = sha256(tokenId);
        var attrs = new JSONObject(token.attributes).toString();

        database.updateUnique("INSERT INTO tokens(token_id, user_id, expiry, attributes) VALUES(?, ?, ?, ?)",
                hashedTokenId,
                token.username,
                token.expiry,
                attrs);

        return tokenId;
    }

    @Override
    public Optional<Token> read(Request request, String tokenId) {
        var hashTokenId = sha256(tokenId);
        return database.findOptional(this::readToken, "SELECT user_id, expiry, attributes " +
                "FROM tokens " +
                "WHERE token_id = ?", hashTokenId);
    }

    @Override
    public void revoke(Request request, String tokenId) {
        var hashTokenId = sha256(tokenId);
        database.updateUnique("DELETE FROM tokens WHERE token_id = ?", hashTokenId);
    }

    private Token readToken(ResultSet res) throws SQLException {
        var i = 1;
        var userId = res.getString(i++);
        var expiry = res.getTimestamp(i++).toInstant();
        var attrsJson = new JSONObject(res.getString(i++));

        var token = new Token(userId, expiry);
        attrsJson.keySet().stream().map(key -> token.attributes.put(key, attrsJson.getString(key)));

        return token;
    }

    public void deleteExpiredToken() {
        database.update("DELETE FROM tokens WHERE expiry < current_timestamp");
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
