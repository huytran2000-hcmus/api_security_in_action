package com.manning.apisecurityinaction;

import static spark.Spark.afterAfter;
import static spark.Spark.before;
import static spark.Spark.exception;
import static spark.Spark.halt;
import static spark.Spark.internalServerError;
import static spark.Spark.notFound;
import static spark.Spark.post;

import java.nio.file.Files;
import java.nio.file.Paths;

import org.dalesbred.Database;
import org.dalesbred.result.EmptyResultException;
import org.h2.jdbcx.JdbcConnectionPool;
import org.json.JSONException;
import org.json.JSONObject;

import com.google.common.util.concurrent.RateLimiter;
import com.manning.apisecurityinaction.controller.SpaceController;
import com.manning.apisecurityinaction.controller.UserController;

import spark.Request;
import spark.Response;

public class Main {
    public static void main(String[] args) throws Exception {
        var datasource = JdbcConnectionPool.create("jdbc:h2:mem:natter", "natter", "password");
        var database = Database.forDataSource(datasource);
        createTables(database);

        datasource = JdbcConnectionPool.create("jdbc:h2:mem:natter", "natter_api_user", "password");
        database = Database.forDataSource(datasource);

        var rateLimiter = RateLimiter.create(2);
        before((request, response) -> {
            if (!rateLimiter.tryAcquire()) {
                response.header("Retry-After", "2");
            }
        });
        before((request, response) -> {
            if (request.requestMethod().equals("POST") && !request.contentType().equals("application/json")) {
                halt(415, new JSONObject().put("error", "Only support application/json").toString());
            }
        });

        var userController = new UserController(database);
        post("/users", userController::registerUser);

        before(userController::authenticate);
        var spaceController = new SpaceController(database);
        post("/spaces", spaceController::createSpace);

        afterAfter((request, response) -> {
            response.header("Server", "");
            response.type("application/json;charset=utf-8");
            response.header("X-Content-Type-Options", "nonsniff");
            response.header("X-Frame-Options", "DENY");
            response.header("Cache-Control", "no-store");
            response.header("X-XSS-Protection", "0");
            response.header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox");
        });

        internalServerError(new JSONObject().put("error", "internal server error").toString());
        notFound(new JSONObject().put("error", "not found").toString());

        exception(IllegalArgumentException.class, Main::badRequest);
        exception(JSONException.class,
                Main::badRequest);
        exception(EmptyResultException.class,
                (e, request, response) -> response.status(404));
    }

    private static void badRequest(Exception ex, Request request, Response response) {
        response.status(400);
        response.body(new JSONObject()
                .put("error", ex.getMessage()).toString());
    }

    private static void createTables(Database database) throws Exception {
        var path = Paths.get(Main.class.getResource("/schema.sql").toURI());
        database.update(Files.readString(path));
    }
}
