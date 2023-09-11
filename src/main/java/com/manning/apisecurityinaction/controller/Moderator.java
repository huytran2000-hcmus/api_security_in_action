package com.manning.apisecurityinaction.controller;

import org.dalesbred.Database;
import org.json.JSONObject;

import spark.Request;
import spark.Response;

public class Moderator {
    private final Database database;

    public Moderator(Database database) {
        this.database = database;
    }

    public JSONObject deletePost(Request request, Response response) {
        var msgId = Long.parseLong(request.params(":msgId"));
        var spaceId = Long.parseLong(request.params(":spaceId"));

        database.updateUnique("DELETE FROM messages " +
                "WHERE msg_id = ? AND space_id = ?",
                msgId, spaceId);
        response.status(204);
        return new JSONObject();
    }
}
