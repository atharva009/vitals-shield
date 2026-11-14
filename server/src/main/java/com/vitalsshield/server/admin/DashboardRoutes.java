package com.vitalsshield.server.admin;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.server.RequestPredicates;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.util.UriUtils;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Serves the dashboard's static export (DECISIONS #47). Explicit RouterFunction (WebFlux auto-config is off). It never
 * matches /api/**, so API controllers always win; PortEnforcementWebFilter keeps it on the admin port.
 *
 * <p>Path safety: the request path is percent-decoded, must not contain backslashes or NUL, is resolved under the
 * directory and normalized, and must still be inside the directory after resolving symlinks. Anything else is 404.
 */
@Configuration(proxyBeanMethods = false)
public class DashboardRoutes {

    static final String NOT_BUILT = "dashboard not built: run npm run build in dashboard/\n";
    static final Pattern INLINE_SCRIPT = Pattern.compile("<script(?![^>]*\\bsrc\\s*=)[^>]*>([\\s\\S]*?)</script>",
            Pattern.CASE_INSENSITIVE);
    static final Map<String, MediaType> TYPES = Map.ofEntries(
            Map.entry("html", MediaType.parseMediaType("text/html;charset=UTF-8")),
            Map.entry("js", MediaType.parseMediaType("text/javascript;charset=UTF-8")),
            Map.entry("css", MediaType.parseMediaType("text/css;charset=UTF-8")),
            Map.entry("json", MediaType.APPLICATION_JSON),
            Map.entry("txt", MediaType.parseMediaType("text/plain;charset=UTF-8")),
            Map.entry("svg", MediaType.parseMediaType("image/svg+xml")),
            Map.entry("png", MediaType.IMAGE_PNG),
            Map.entry("ico", MediaType.parseMediaType("image/x-icon")),
            Map.entry("woff2", MediaType.parseMediaType("font/woff2")),
            Map.entry("map", MediaType.APPLICATION_JSON));

    private record Cached(long lastModified, String csp) {
    }

    private final Map<Path, Cached> cspCache = new ConcurrentHashMap<>();

    @Bean
    public RouterFunction<ServerResponse> dashboardRouter(DashboardProperties props) {
        return RouterFunctions.route(
                // GET and HEAD (HEAD mirrors GET headers, e.g. curl -I); never /api/**.
                RequestPredicates.GET("/**").or(RequestPredicates.HEAD("/**"))
                        .and(req -> !req.path().startsWith("/api/")),
                req -> serve(req, props.dir()));
    }

    Mono<ServerResponse> serve(ServerRequest req, Path dir) {
        return Mono.fromCallable(() -> resolve(dir, req.path()))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(target -> target.map(this::respond).orElseGet(() -> notFoundOrNotBuilt(dir, req.path())));
    }

    /** The file to serve, or empty for 404. Never escapes {@code dir}. */
    static Optional<Path> resolve(Path dir, String rawPath) throws IOException {
        if (!Files.isDirectory(dir)) {
            return Optional.empty();
        }
        String decoded;
        try {
            decoded = UriUtils.decode(rawPath, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
        if (decoded.indexOf('\0') >= 0 || decoded.indexOf('\\') >= 0 || !decoded.startsWith("/")) {
            return Optional.empty();
        }
        Path root = dir.toRealPath();
        Path candidate = root.resolve(decoded.substring(1)).normalize();
        if (!candidate.startsWith(root)) {
            return Optional.empty();
        }
        if (Files.isDirectory(candidate)) {
            candidate = candidate.resolve("index.html");
        } else if (!Files.exists(candidate) && !decoded.substring(decoded.lastIndexOf('/') + 1).contains(".")) {
            candidate = candidate.resolveSibling(candidate.getFileName() + ".html");
        }
        if (!Files.isRegularFile(candidate)) {
            return Optional.empty();
        }
        Path real = candidate.toRealPath();
        return real.startsWith(root) ? Optional.of(real) : Optional.empty();
    }

    private Mono<ServerResponse> respond(Path file) {
        return Mono.fromCallable(() -> Files.readAllBytes(file))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMap(bytes -> {
                    String ext = ext(file);
                    ServerResponse.BodyBuilder b = ServerResponse.ok()
                            .contentType(TYPES.getOrDefault(ext, MediaType.APPLICATION_OCTET_STREAM));
                    if ("html".equals(ext)) {
                        b.header("Content-Security-Policy", cspFor(file, bytes));
                        b.header("Cache-Control", "no-cache");
                    }
                    return b.bodyValue(bytes);
                });
    }

    private Mono<ServerResponse> notFoundOrNotBuilt(Path dir, String path) {
        if (!Files.isDirectory(dir) && "/".equals(path)) {
            return ServerResponse.ok().contentType(MediaType.TEXT_PLAIN).bodyValue(NOT_BUILT);
        }
        return ServerResponse.status(HttpStatus.NOT_FOUND).build();
    }

    /**
     * The admin CSP with script-src extended by the SHA-256 of every inline script in this HTML file (DECISIONS #52),
     * so the Next.js export runs without 'unsafe-inline'. Cached per file and modification time.
     */
    String cspFor(Path file, byte[] html) {
        long modified;
        try {
            modified = Files.getLastModifiedTime(file).toMillis();
        } catch (IOException e) {
            modified = -1;
        }
        Cached c = cspCache.get(file);
        if (c != null && c.lastModified() == modified) {
            return c.csp();
        }
        Set<String> hashes = new LinkedHashSet<>();
        Matcher m = INLINE_SCRIPT.matcher(new String(html, StandardCharsets.UTF_8));
        while (m.find()) {
            hashes.add("'sha256-" + Base64.getEncoder().encodeToString(sha256(m.group(1))) + "'");
        }
        String csp = hashes.isEmpty() ? AdminSecurityHeadersWebFilter.CSP
                : AdminSecurityHeadersWebFilter.CSP.replace("script-src 'self'",
                        "script-src 'self' " + String.join(" ", hashes));
        cspCache.put(file, new Cached(modified, csp));
        return csp;
    }

    private static String ext(Path file) {
        String n = file.getFileName().toString();
        int dot = n.lastIndexOf('.');
        return dot < 0 ? "" : n.substring(dot + 1).toLowerCase(Locale.ROOT);
    }

    private static byte[] sha256(String s) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
