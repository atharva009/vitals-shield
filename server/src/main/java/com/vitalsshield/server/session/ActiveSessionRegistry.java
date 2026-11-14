package com.vitalsshield.server.session;

import com.vitalsshield.server.pki.trust.CertKey;
import io.netty.channel.Channel;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Live mTLS connections by certificate. A Channel is Netty's handle on one TCP connection; closing it ends the
 * connection, including an idle keep-alive one. Each channel removes itself when it closes.
 */
@Component
public class ActiveSessionRegistry {

    private final Map<CertKey, Set<Channel>> channels = new ConcurrentHashMap<>();

    public void register(CertKey key, Channel channel) {
        channels.computeIfAbsent(key, k -> ConcurrentHashMap.newKeySet()).add(channel);
        channel.closeFuture().addListener(f -> remove(key, channel));
    }

    public int liveSocketCount() {
        return channels.values().stream().mapToInt(Set::size).sum();
    }

    /** Live socket count per certificate (for the dashboard). */
    public Map<CertKey, Integer> liveCountsByKey() {
        Map<CertKey, Integer> out = new java.util.HashMap<>();
        channels.forEach((k, set) -> {
            if (!set.isEmpty()) {
                out.put(k, set.size());
            }
        });
        return out;
    }

    public Set<Channel> liveSocketsFor(CertKey key) {
        Set<Channel> set = channels.get(key);
        return set == null ? Set.of() : Set.copyOf(set);
    }

    /** Closes every channel for {@code key}; completes with the number closed once all close futures complete. */
    public Mono<Integer> evictByCert(CertKey key) {
        List<Channel> targets = List.copyOf(liveSocketsFor(key));
        if (targets.isEmpty()) {
            return Mono.just(0);
        }
        return Flux.fromIterable(targets)
                .flatMap(ch -> Mono.<Void>create(sink -> ch.close().addListener(f -> sink.success())))
                .then(Mono.just(targets.size()));
    }

    private void remove(CertKey key, Channel channel) {
        channels.computeIfPresent(key, (k, set) -> {
            set.remove(channel);
            return set.isEmpty() ? null : set;
        });
    }
}
