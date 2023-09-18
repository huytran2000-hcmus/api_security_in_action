package com.manning.apisecurityinaction;

import static spark.Spark.halt;

import java.util.Set;

import spark.Filter;
import spark.Request;
import spark.Response;

public class CORSFilter implements Filter {
    private final Set<String> allowOrigins;

    public CORSFilter(String... origins) {
        this.allowOrigins = Set.of(origins);
    }

    @Override
    public void handle(Request request, Response response) throws Exception {
        var originHeader = request.headers("Origin");
        response.header("Vary", "Origin");
        if (originHeader != null && originHeader != "" && allowOrigins.contains(originHeader)) {
            response.header("Access-Control-Allow-Origin", originHeader);
            // response.header("Access-Control-Allow-Credentials", "true");
        }

        if (isPreflightRequest(request)) {
            if (originHeader == null || !allowOrigins.contains(originHeader)) {
                halt(403);
            }

            response.header("Access-Control-Allow-Methods", "GET, POST, DELETE");
            response.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
            halt(204);
        }
    }

    private boolean isPreflightRequest(Request request) {
        return "OPTIONS".equals(request.requestMethod()) &&
                request.headers().contains("Access-Control-Request-Method");
    }
}
