package com.manning.apisecurityinaction;

import static org.jsoup.Connection.Method.GET;
import static spark.Spark.afterAfter;
import static spark.Spark.exception;
import static spark.Spark.get;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.UnknownHostException;

import org.json.JSONObject;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
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
            var doc = fetch(url);
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

    public static Document fetch(String url) throws IOException {
        Document doc = null;
        int retries = 0;
        while (doc == null && retries++ < 10) {
            if (isBlockedAddress(url)) {
                throw new IllegalArgumentException("URL refers to local/private address");
            }
            var res = Jsoup.connect(url).followRedirects(false).timeout(5000).method(GET).execute();
            if (res.statusCode() / 100 == 3) {
                url = res.header("Location");
            } else {
                doc = res.parse();
            }
        }

        if (doc == null)
            throw new IOException("Too many requests");
        return doc;
    }

    private static <T extends Exception> ExceptionHandler<T> handleException(int status) {
        return (ex, request, response) -> {
            logger.error("Caught error  {} - returning status {}", ex, status);
            response.status(status);
            response.body(new JSONObject().put("status", status).toString());
        };
    }

    private static boolean isBlockedAddress(String url) throws UnknownHostException {
        var host = URI.create(url).getHost();
        for (var ipAddr : InetAddress.getAllByName(url)) {
            if (ipAddr.isLoopbackAddress() || ipAddr.isLinkLocalAddress() || ipAddr.isSiteLocalAddress()
                    || ipAddr.isMulticastAddress() || ipAddr.isAnyLocalAddress() || isUniqueLocalAddress(ipAddr)) {
                return true;
            }
        }

        return false;
    }

    private static boolean isUniqueLocalAddress(InetAddress ipAddress) {
        return ipAddress instanceof Inet6Address &&
                (ipAddress.getAddress()[0] == 0xFF) &&
                (ipAddress.getAddress()[1] == 0x00);
    }
}
