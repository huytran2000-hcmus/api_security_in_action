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

public class AuditController {
    private final Database database;
    private final String auditAttrKey = "audit_id";

    public AuditController(Database database) {
        this.database = database;
    }

    public JSONArray readAuditLogs(Request request, Response response) {
        var since = Instant.now().minus(1, ChronoUnit.HOURS);
        var logs = database.findAll(AuditController::recordToJson,
                "SELECT audit_id, method, path, status, user_id, audit_time " +
                        "FROM audit_log " +
                        "WHERE audit_time > ?",
                since);
        return new JSONArray(logs);
    }

    public void logRequest(Request request, Response response) {
        database.withVoidTransaction(tx -> {
            var auditId = database.findUniqueLong("SELECT NEXT VALUE FOR audit_id_seq");
            System.out.println(auditId);
            request.attribute(auditAttrKey, auditId);
            database.updateUnique(
                    "INSERT INTO audit_log(audit_id, method, path, user_id, audit_time)" +
                            "VALUES(?, ?, ?, ?, current_timestamp)",
                    auditId,
                    request.requestMethod(),
                    request.pathInfo(),
                    request.attribute(UserController.authAttrKey));
        });
    }

    public void logResponse(Request request, Response response) {
        database.withVoidTransaction(tx -> {
            database.updateUnique(
                    "INSERT INTO audit_log(audit_id, method, path, status, user_id, audit_time)" +
                            "VALUES(?, ?, ?, ?, ?, current_timestamp)",
                    request.attribute(auditAttrKey),
                    request.requestMethod(),
                    request.pathInfo(),
                    response.status(),
                    request.attribute(UserController.authAttrKey));
        });
    }

    private static JSONObject recordToJson(ResultSet row) throws SQLException {
        return new JSONObject().put("audit_id", row.getLong("audit_id")).put("method", row.getString("method"))
                .put("path", row.getString("path")).put("status", row.getString("status"))
                .put("user_id", row.getString("user_id")).put("audit_time", row.getString("audit_time"));
    }
}
