package com.manning.apisecurityinaction.controller;

import java.sql.SQLException;

import org.dalesbred.Database;
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
        var subject = request.attribute(UserController.authAttrKey);
        if (!owner.equals(subject)) {
            throw new IllegalArgumentException("owner must match authenticated user");
        }

        return database.withTransaction(tx -> {
            var spaceId = database.findUniqueLong("SELECT NEXT VALUE FOR space_id_seq");
            database.updateUnique("INSERT INTO spaces (space_id, name, owner) VALUES(" + spaceId + ", '" + spaceName
                    + "', '" + owner + "');");

            response.status(201);
            var uri = "/spaces/" + spaceId;
            response.header("Location", uri);

            return new JSONObject().put("name", spaceName).put("uri", uri).put("owner", owner);
        });
    }
}
