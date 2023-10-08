package com.manning.apisecurityinaction.controller;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.stream.Collectors;

import org.dalesbred.Database;
import org.json.JSONArray;
import org.json.JSONObject;

import com.manning.apisecurityinaction.controller.UserController.Permission;

import spark.Request;
import spark.Response;

public class SpaceController {
    private static final Set<String> DEFINED_ROLES = Set.of("owner", "moderator", "member", "observer");
    private final Database database;
    private final CapabilityController capCtrl;

    public SpaceController(Database database, CapabilityController capCtrl) {
        this.database = database;
        this.capCtrl = capCtrl;
    }

    public JSONObject createSpace(Request request, Response response) throws SQLException {
        var json = new JSONObject(request.body());
        var spaceName = json.getString("name");
        if (spaceName.length() > 255) {
            throw new IllegalArgumentException("space name is too long");
        }

        var owner = json.getString("owner");
        var subject = request.attribute(UserController.USERNAME_ATTR_KEY);
        if (!owner.equals(subject)) {
            throw new IllegalArgumentException("owner must match authenticated user");
        }

        return database.withTransaction(tx -> {
            var spaceId = database.findUniqueLong("SELECT NEXT VALUE FOR space_id_seq");
            database.updateUnique("INSERT INTO spaces (space_id, name, owner) VALUES(?, ?, ?);", spaceId, spaceName,
                    owner);
            database.updateUnique("INSERT INTO user_roles (space_id, user_id, role_id) " +
                    "VALUES(?, ?, ?);",
                    spaceId, owner, "owner");

            var expiry = Duration.ofDays(100000);
            var spacePath = "/spaces/" + spaceId;
            var msgPath = spacePath + "/messages";

            var uri = capCtrl.createUri(request, spacePath, Permission.full, expiry);
            var readOnlyUri = capCtrl.createUri(request, spacePath, Permission.read, expiry);
            var msgsUri = capCtrl.createUri(request, msgPath, Permission.full, expiry);
            var msgsReadWriteUri = capCtrl.createUri(request, msgPath, Permission.read.combine(Permission.write),
                    expiry);
            var msgsReadOnlyUri = capCtrl.createUri(request, msgPath, Permission.read, expiry);

            response.status(201);
            response.header("Location", uri.toASCIIString());

            return new JSONObject().put("name", spaceName).put("owner", owner).put("uri", uri)
                    .put("uri-r", readOnlyUri)
                    .put("messages-rwd", msgsUri).put("messages-rw", msgsReadWriteUri)
                    .put("messages-r", msgsReadOnlyUri);
        });
    }

    public JSONObject addMember(Request request, Response response) {
        var json = new JSONObject(request.body());
        var spaceId = Long.parseLong(request.params(":spaceId"));
        var userToAdd = json.getString("username");
        var role = json.optString("role", "member");

        if (!DEFINED_ROLES.contains(role)) {
            throw new IllegalArgumentException("invalid role");
        }

        database.updateUnique(
                "INSERT INTO user_roles(space_id, user_id, role_id) " +
                        "VALUES(?, ?, ?)",
                spaceId, userToAdd, role);

        response.status(200);
        return new JSONObject()
                .put("username", userToAdd)
                .put("role", role);
    }

    public JSONObject readSpace(Request request, Response response) {
        var spaceId = Long.parseLong(request.params(":spaceId"));

        var space = database.findUnique(Space.class,
                "SELECT space_id, name, owner " +
                        "FROM spaces " +
                        "WHERE space_id = ?",
                spaceId);

        response.status(200);

        var expiry = Duration.ofDays(100000);
        var spacePath = "/spaces/" + spaceId;
        var msgPath = spacePath + "/messages";
        Permission perms = request.attribute(UserController.PERMS_ATTR_KEY);
        var msgsUri = capCtrl.createUri(request, msgPath, perms, expiry);

        var spaceJson = new JSONObject().put("id", space.spaceId).put("name", space.name);
        return new JSONObject().put("space", spaceJson).put("messages", msgsUri);
    }

    public JSONObject postMessage(Request request, Response response) {
        var json = new JSONObject(request.body());
        var userId = json.getString("author");
        if (!userId.equals(request.attribute(UserController.USERNAME_ATTR_KEY))) {
            throw new IllegalArgumentException("author must match authenticated user");
        }

        var message = json.getString("message");
        if (message.length() > 1024) {
            throw new IllegalArgumentException("message is too long");
        }

        var spaceId = Long.parseLong(request.params(":spaceId"));

        return database.withTransaction(tx -> {
            var msgId = database.findUniqueLong("SELECT NEXT VALUE FOR msg_id_seq");
            database.updateUnique(
                    "INSERT INTO messages(msg_id, author, space_id, msg_time, msg_text) VALUES(? ,?, ?, current_timestamp, ?)",
                    msgId, userId, spaceId, message);

            response.status(201);
            var msgPath = "/spaces/" + spaceId + "/messages/" + msgId;
            var msgUri = capCtrl.createUri(request, msgPath, Permission.read.combine(Permission.write),
                    Duration.ofMinutes(5));
            var msgReadOnlyUri = capCtrl.createUri(request, msgPath, Permission.read,
                    Duration.ofDays(365));

            response.header("Location", msgPath);
            return new JSONObject().put("uri", msgUri).put("uri-r", msgReadOnlyUri);
        });
    }

    public Message readMessage(Request request, Response response) {
        var msgId = Long.parseLong(request.params(":msgId"));
        var spaceId = Long.parseLong(request.params(":spaceId"));
        var msg = database.findUnique(Message.class,
                "SELECT msg_id, space_id, author, msg_time, msg_text " +
                        "FROM messages " +
                        "WHERE msg_id = ? AND space_id = ?",
                msgId, spaceId);

        response.status(200);
        return msg;
    }

    public JSONArray findMessages(Request request, Response response) {
        Instant since;
        if (request.queryParams("since") != null) {
            since = Instant.parse(request.queryParams("since"));
        } else {
            since = Instant.now().minus(1, ChronoUnit.DAYS);
        }
        var spaceId = Long.parseLong(request.params(":spaceId"));
        var messages = database.findAll(Long.class,
                "SELECT msg_id " +
                        "FROM messages " +
                        "WHERE space_id = ? AND msg_time > ?",
                spaceId, since);

        response.status(200);
        var perms = request.<Permission>attribute(UserController.PERMS_ATTR_KEY).subtract(Permission.write);
        return new JSONArray(messages.stream().map(id -> "/spaces/" + spaceId + "/messages/" + id)
                .map(path -> capCtrl.createUri(request, path, perms, Duration.ofMinutes(10)))
                .collect(Collectors.toList()));
    }

    public static class Space {
        private final long spaceId;
        private final String name;
        private final String owner;

        public Space(long spaceId, String name, String owner) {
            this.spaceId = spaceId;
            this.name = name;
            this.owner = owner;
        }

        @Override
        public String toString() {
            var space = new JSONObject()
                    .put("id", spaceId)
                    .put("name", name)
                    .put("owner", owner);

            return space.toString();
        }
    }

    public static class Message {
        private final long msgId;
        private final long spaceId;
        private final String author;
        private final Instant msgTime;
        private final String msgText;

        public Message(long msgId, long spaceId, String author, Instant msgTime, String msgText) {
            this.msgId = msgId;
            this.spaceId = spaceId;
            this.author = author;
            this.msgTime = msgTime;
            this.msgText = msgText;
        }

        @Override
        public String toString() {
            var msg = new JSONObject()
                    .put("id", msgId)
                    .put("space_id", spaceId)
                    .put("author", author)
                    .put("msg_time", msgTime)
                    .put("msg_text", msgText);

            return msg.toString();
        }

        public static JSONObject recordToJson(ResultSet row) throws SQLException {
            return new JSONObject()
                    .put("id", row.getLong("msg_id"))
                    .put("space_id", row.getLong("space_id"))
                    .put("author", row.getString("author"))
                    .put("msg_time", row.getString("msg_time"))
                    .put("msg_text", row.getString("msg_text"));
        }
    }
}
