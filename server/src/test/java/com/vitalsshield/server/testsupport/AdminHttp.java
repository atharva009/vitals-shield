package com.vitalsshield.server.testsupport;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import tools.jackson.databind.json.JsonMapper;

/**
 * HTTP client for the admin plane in webauthn mode: http://localhost:port, the browser's Origin header on every
 * POST, and the session cookie kept after sign-in (a cookie jar of one).
 */
public final class AdminHttp {

    public record Response(int status, String body, java.net.http.HttpHeaders headers) {
        @SuppressWarnings("unchecked")
        public Map<String, Object> json() {
            return JSON.readValue(body, Map.class);
        }
    }

    private static final JsonMapper JSON = JsonMapper.builder().build();

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final int port;
    private final String origin;
    private String cookie;

    public AdminHttp(int port) {
        this.port = port;
        this.origin = "http://localhost:" + port;
    }

    public String origin() {
        return origin;
    }

    public String cookie() {
        return cookie;
    }

    public void cookie(String c) {
        this.cookie = c;
    }

    public Response get(String path) {
        return send(HttpRequest.newBuilder(uri(path)).GET(), null);
    }

    public Response post(String path, String json) {
        return post(path, json, origin, null);
    }

    public Response post(String path, String json, String originOrNull, String bearerOrNull) {
        HttpRequest.Builder b = HttpRequest.newBuilder(uri(path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json == null ? "{}" : json));
        if (originOrNull != null) {
            b.header("Origin", originOrNull);
        }
        if (bearerOrNull != null) {
            b.header("Authorization", "Bearer " + bearerOrNull);
        }
        return send(b, null);
    }

    private Response send(HttpRequest.Builder b, Void unused) {
        if (cookie != null) {
            b.header("Cookie", cookie);
        }
        try {
            HttpResponse<String> r = http.send(b.timeout(Duration.ofSeconds(20)).build(),
                    HttpResponse.BodyHandlers.ofString());
            r.headers().firstValue("Set-Cookie").ifPresent(c -> {
                String pair = c.split(";", 2)[0];
                cookie = pair.endsWith("=") ? null : pair;
            });
            return new Response(r.statusCode(), r.body(), r.headers());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private URI uri(String path) {
        return URI.create("http://localhost:" + port + path);
    }

    public static String json(Map<String, ?> m) {
        return JSON.writeValueAsString(m);
    }
}
