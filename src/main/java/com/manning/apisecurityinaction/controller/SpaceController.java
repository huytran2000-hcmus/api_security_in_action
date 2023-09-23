package com.manning.apisecurityinaction.controller;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.dalesbred.Database;
import org.json.JSONArray;
import org.json.JSONObject;

import spark.Request;
import spark.Response;

public class SpaceController {
    private final Database database;

    public SpaceController(Database database) {
        this.database = database;
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
            database.updateUnique("INSERT INTO permissions (space_id, user_id, perms) " +
                    "VALUES(?, ?, ?);",
                    spaceId, owner, "rwd");

            response.status(201);
            var uri = "/spaces/" + spaceId;
            response.header("Location", uri);

            return new JSONObject().put("name", spaceName).put("uri", uri).put("owner", owner);
        });
    }

    public JSONObject addMember(Request request, Response response) {
        var json = new JSONObject(request.body());
        var spaceId = Long.parseLong(request.params(":spaceId"));
        var userToAdd = json.getString("username");
        var perms = json.getString("permissions");

        if (!perms.matches("r?w?d?")) {
            throw new IllegalArgumentException("invalid permissions");
        }

        database.updateUnique(
                "INSERT INTO permissions(space_id, user_id, perms) " +
                        "VALUES(?, ?, ?)",
                spaceId, userToAdd, perms);

        response.status(200);
        return new JSONObject()
                .put("username", userToAdd)
                .put("permissions", perms);
    }

    public Space readSpace(Request request, Response response) {
        var spaceId = Long.parseLong(request.params(":spaceId"));

        var space = database.findUnique(Space.class,
                "SELECT space_id, name, owner " +
                        "FROM spaces " +
                        "WHERE space_id = ?",
                spaceId);

        response.status(200);
        return space;
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
            var uri = "/spaces/" + spaceId + "/messages/" + msgId;
            response.header("Location", uri);
            return new JSONObject().put("uri", uri);
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
        var messages = database.findAll(Message::recordToJson,
                "SELECT msg_id, author, space_id, msg_time, msg_text " +
                        "FROM messages " +
                        "WHERE space_id = ? AND msg_time > ?",
                spaceId, since);

        response.status(200);
        return new JSONArray(messages);
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
