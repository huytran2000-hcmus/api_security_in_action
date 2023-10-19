package com.manning.apisecurityinaction;

import static spark.Spark.afterAfter;
import static spark.Spark.before;
import static spark.Spark.delete;
import static spark.Spark.exception;
import static spark.Spark.get;
import static spark.Spark.halt;
import static spark.Spark.internalServerError;
import static spark.Spark.notFound;
import static spark.Spark.port;
import static spark.Spark.post;
import static spark.Spark.staticFiles;

import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.Set;

import javax.crypto.SecretKey;

import org.dalesbred.Database;
import org.dalesbred.result.EmptyResultException;
import org.h2.jdbcx.JdbcConnectionPool;
import org.json.JSONException;
import org.json.JSONObject;

import com.google.common.util.concurrent.RateLimiter;
import com.manning.apisecurityinaction.controller.AuditController;
import com.manning.apisecurityinaction.controller.CapabilityController;
import com.manning.apisecurityinaction.controller.DroolsAccessController;
import com.manning.apisecurityinaction.controller.Moderator;
import com.manning.apisecurityinaction.controller.SpaceController;
import com.manning.apisecurityinaction.controller.TokenController;
import com.manning.apisecurityinaction.controller.UserController;
import com.manning.apisecurityinaction.controller.UserController.Permission;
import com.manning.apisecurityinaction.token.DatabaseTokenStore;
import com.manning.apisecurityinaction.token.EncryptedJwtTokenStore;
import com.manning.apisecurityinaction.token.MacaroonTokenStore;
import com.manning.apisecurityinaction.token.SecureTokenStore;

import spark.Request;
import spark.Response;

public class Main {
    public static void main(String[] args) throws Exception {
        port(args.length > 0 ? Integer.parseInt(args[0]) : spark.Service.SPARK_DEFAULT_PORT);

        staticFiles.location("/public");
        staticFiles.expireTime(1);
        // secure("localhost.p12",
        // "changeit",
        // null,
        // null);

        var jdbcUrl = "jdbc:h2:tcp://natter-database-service:9092/mem:natter";
        var datasource = JdbcConnectionPool.create(jdbcUrl, "natter", "password");
        var database = Database.forDataSource(datasource);
        createTables(database);

        datasource = JdbcConnectionPool.create(jdbcUrl, "natter_api_user", "password");
        database = Database.forDataSource(datasource);

        var keyPassword = System.getProperty("keystore.password",
                "changeit").toCharArray();
        var keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream("keystore.p12"), keyPassword);

        // var allowlistStore = new DatabaseTokenStore(database);
        var encKey = keyStore.getKey("aes-key", keyPassword);
        SecureTokenStore tokenStore = new EncryptedJwtTokenStore((SecretKey) encKey, "https://localhost:4567");

        var macKey = keyStore.getKey("hmac-key", keyPassword);
        // var algorithm = JWSAlgorithm.HS256;
        // var singer = new MACSigner((SecretKey) macKey);
        // var verifier = new MACVerifier((SecretKey) macKey);
        // var tokenStore = new SignedJwtTokenStore(singer, algorithm, verifier,
        // "https://localhost:4567");

        // var introspectionUri =
        // URI.create("http://as.example.com:8080/oauth2/introspect");
        // var revocationUri = URI.create("http://as.example.com:8080/oauth2/revoke");
        // SecureTokenStore tokenStore = new OAuth2TokenStore(introspectionUri,
        // revocationUri, "test", "password");

        var dbTokenStore = new DatabaseTokenStore(database);
        var capabilityStore = MacaroonTokenStore.wrap(dbTokenStore, macKey);

        var tokenCtrl = new TokenController(tokenStore);
        var capabilityCtrl = new CapabilityController(capabilityStore);
        var userCtrl = new UserController(database);
        var auditCtrl = new AuditController(database);
        var spaceCtrl = new SpaceController(database, capabilityCtrl);
        var moderatorCtrl = new Moderator(database);
        var droolCtrl = new DroolsAccessController();

        before(new CORSFilter("https://localhost:9999"));

        var rateLimiter = RateLimiter.create(2);
        before((request, response) -> {
            if (!rateLimiter.tryAcquire()) {
                response.header("Retry-After", "2");
            }
        });

        var expectedHostNames = Set.of(
                "api.natter.com",
                "api.natter.com:4567",
                "natter-link-preview-service:4567",
                "natter-link-preview-service.natter-api:4567",
                "natter-link-preview-service.natter-api.svc.cluster.local:4567");
        before((request, response) -> {
            if (!expectedHostNames.contains(request.host())) {
                halt(400);
            }
        });
        before((request, response) -> {
            if (request.requestMethod().equals("POST") && !request.contentType().equals("application/json")) {
                halt(415, new JSONObject().put("error", "Only support application/json").toString());
            }
        });
        before(userCtrl::authenticate);
        before(tokenCtrl::validateToken);
        before(auditCtrl::logRequest);
        before(droolCtrl::enforcePolicy);

        before("/sessions", userCtrl.requireScope("POST", "full_access"));
        before("/sessions", userCtrl::requireAuthentication);
        post("/sessions", tokenCtrl::login);
        delete("/logout", tokenCtrl::logout);

        get("/logs", auditCtrl::readAuditLogs);

        post("/users", userCtrl::registerUser);

        before("/spaces", userCtrl::requireAuthentication);
        before("/spaces", userCtrl.requireScope("POST", "create_space"));
        post("/spaces", spaceCtrl::createSpace);

        before("/spaces/:spaceId", userCtrl::lookupPermissions);
        before("/spaces/:spaceId", capabilityCtrl::lookupPermissions);
        before("/spaces/:spaceId", userCtrl.requireScope("GET", "read_space"));
        before("/spaces/:spaceId", userCtrl.requirePermission("GET",
                Permission.read));
        get("/spaces/:spaceId", spaceCtrl::readSpace);

        before("/spaces/:spaceId/*", userCtrl::lookupPermissions);
        before("/spaces/:spaceId/*", capabilityCtrl::lookupPermissions);

        before("/spaces/:spaceId/messages", userCtrl.requireScope("POST", "post_message"));
        before("/spaces/:spaceId/messages", userCtrl.requirePermission("POST", Permission.write));
        post("/spaces/:spaceId/messages", spaceCtrl::postMessage);

        before("/spaces/:spaceId/messages*", userCtrl.requireScope("GET", "read_message"));
        before("/spaces/:spaceId/messages", userCtrl.requirePermission("GET", Permission.read));
        get("/spaces/:spaceId/messages", spaceCtrl::findMessages);
        before("/spaces/:spaceId/messages/*", userCtrl.requirePermission("GET", Permission.read));
        get("/spaces/:spaceId/messages/:msgId", spaceCtrl::readMessage);

        before("/spaces/:spaceId/messages/*", userCtrl.requireScope("DELETE", "delete_message"));
        before("/spaces/:spaceId/messages/*", userCtrl.requirePermission("DELETE", Permission.delete));
        delete("/spaces/:spaceId/messages/:msgId", moderatorCtrl::deletePost);

        before("/spaces/:spaceId/members", userCtrl.requireScope("POST", "add_member"));
        before("/spaces/:spaceId/members", userCtrl.requirePermission("POST",
                Permission.full));
        post("/spaces/:spaceId/members", spaceCtrl::addMember);

        before("/capabilities", userCtrl::requireAuthentication);
        post("/capabilities", capabilityCtrl::share);

        afterAfter((request, response) -> {
            response.header("Server", "");
            response.type("application/json;charset=utf-8");
            response.header("X-Content-Type-Options", "nonsniff");
            response.header("X-Frame-Options", "DENY");
            response.header("Cache-Control", "no-store");
            response.header("X-XSS-Protection", "0");
            response.header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox");
            response.header("Strict-Transport-Sercurity", "max-age=31536000");
        });
        afterAfter(auditCtrl::logResponse);

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
