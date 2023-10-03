package com.manning.apisecurityinaction.controller;

import static spark.Spark.halt;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Set;

import org.dalesbred.Database;
import org.json.JSONObject;

import com.lambdaworks.crypto.SCryptUtil;

import spark.Filter;
import spark.Request;
import spark.Response;

public class UserController {
    public static final String USERNAME_ATTR_KEY = "user_id";
    public static final String ATTRS_ATTR_KEY = "attributes";
    public static final String SCOPE_ATTR_KEY = "scope";

    public static final String USERNAME_PATTERN = "[a-zA-Z][a-zA-Z0-9]{1,29}";
    private static final String authPrefix = "Basic ";
    private final Database database;

    public UserController(Database database) {
        this.database = database;
    }

    public JSONObject registerUser(Request request, Response response) throws Exception {
        var json = new JSONObject(request.body());
        var username = json.getString("username");
        var password = json.getString("password");

        if (!username.matches(USERNAME_PATTERN)) {
            throw new IllegalArgumentException("invalid username");
        }

        if (password.length() < 8) {
            throw new IllegalArgumentException("password must be at least 8 characters");
        }

        var hash = SCryptUtil.scrypt(password, 32768, 8, 1);
        database.updateUnique("INSERT INTO users(user_id, pw_hash)" +
                "VALUES(?, ?)", username, hash);
        response.status(201);
        response.header("Location", "/user/" + username);
        return new JSONObject().put("username", username);
    }

    public void authenticate(Request request, Response response) {
        var authHeader = request.headers("Authorization");
        if (authHeader == null || !authHeader.startsWith(authPrefix)) {
            return;
        }

        var offset = authPrefix.length();
        var credentials = new String(Base64.getDecoder().decode(
                authHeader.substring(offset)), StandardCharsets.UTF_8);

        var parts = credentials.split(":");
        if (parts.length != 2) {
            throw new IllegalArgumentException("invalid Authorization header");
        }

        var username = parts[0];
        var password = parts[1];

        var hash = database.findOptional(String.class,
                "SELECT pw_hash FROM users where user_id = ?", username);
        if (hash.isPresent() &&
                SCryptUtil.check(password, hash.get())) {
            request.attribute(USERNAME_ATTR_KEY, username);

            var groups = database.findAll(String.class, "SELECT DISTINCT group_id " +
                    "FROM group_members " +
                    "WHERE user_id = ?",
                    username);
            request.attribute("groups", groups);
        }
    }

    public void requireAuthentication(Request request, Response response) {
        var username = request.attribute(USERNAME_ATTR_KEY);
        if (username == null) {
            response.status(401);
            response.header("WWW-Authenticate", "Bearer");
            halt(401);
        }
    }

    public void lookupPermissions(Request request, Response response) {
        requireAuthentication(request, response);
        var spaceId = Long.parseLong(request.params(":spaceId"));
        var username = (String) request.attribute(USERNAME_ATTR_KEY);

        var perms = database.findOptional(String.class,
                "SELECT rp.perms " +
                        "FROM role_permissions rp join user_roles ur ON rp.role_id = ur.role_id " +
                        "where ur.space_id = ? AND ur.user_id = ?",
                spaceId,
                username).orElse("");
        request.attribute("perms", perms);
    }

    public Filter requirePermission(String method, String permission) {
        return (request, response) -> {
            if (!method.equalsIgnoreCase(request.requestMethod())) {
                return;
            }

            requireAuthentication(request, response);
            String perms = request.attribute("perms");
            if (perms == null || !perms.contains(permission)) {
                halt(403);
            }
        };
    }

    public Filter requireScope(String method, String requireScope) {
        return (request, response) -> {
            if (!method.equalsIgnoreCase(method)) {
                return;
            }

            var tokenScope = request.<String>attribute("scope");
            if (tokenScope == null)
                return;

            if (!Set.of(tokenScope.split(" ")).contains(requireScope)) {
                response.header("WWW-Authenticate", "Bearer error=\"insufficient_scope\"," +
                        "scope=\"" + requireScope + "\"");
                halt(403);
            }
        };
    }
}
