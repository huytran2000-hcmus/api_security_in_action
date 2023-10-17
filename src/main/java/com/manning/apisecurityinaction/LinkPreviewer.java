package com.manning.apisecurityinaction;

import static spark.Spark.afterAfter;
import static spark.Spark.exception;
import static spark.Spark.get;

import java.net.MalformedURLException;
import java.net.UnknownHostException;

import org.json.JSONObject;
import org.jsoup.Jsoup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import spark.ExceptionHandler;

public class LinkPreviewer {
    private static final Logger logger = LoggerFactory.getLogger(LinkPreviewer.class);

    public static void main(String... args) {
        afterAfter((request, response) -> {
            response.type("application/json; charset=utf-8");
        });

        get("/preview", (request, response) -> {
            var url = request.queryParams("url");
            var doc = Jsoup.connect(url).timeout(3000).get();
            var title = doc.title();
            var description = doc.head().selectFirst("meta[property='og:description']");
            var img = doc.head().selectFirst("meta[property='og:image']");

            return new JSONObject()
                    .put("url", doc.location())
                    .putOpt("title", title)
                    .putOpt("description", description == null ? null : description.attr("content"))
                    .putOpt("image", img == null ? null : img.attr("content"));
        });

        exception(IllegalArgumentException.class, handleException(400));
        exception(MalformedURLException.class, handleException(400));
        exception(Exception.class, handleException(502));
        exception(UnknownHostException.class, handleException(404));
    }

    private static <T extends Exception> ExceptionHandler<T> handleException(int status) {
        return (ex, request, response) -> {
            logger.error("Caught error  {} - returning status {}", ex, status);
            response.status(status);
            response.body(new JSONObject().put("status", status).toString());
        };
    }
}
