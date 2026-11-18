package com.vitalsshield.server.testsupport;

import com.nimbusds.jose.util.JSONObjectUtils;
import com.vitalsshield.crypto.CsrFactory;
import com.vitalsshield.crypto.EcKeys;
import com.vitalsshield.simulator.GatewayClient;
import com.vitalsshield.simulator.Simulator;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.text.ParseException;
import java.util.Base64;
import java.util.Map;

/** Protocol C from a test: GET /challenge, build and POST /re-enroll bodies (valid or deliberately broken). */
public final class ReEnrolls {

    private ReEnrolls() {
    }

    public record Challenge(long issuedAtMs, byte[] nonce, String tagB64) {
    }

    public static Challenge challenge(TestPorts.Listeners ports, Path trustFile, String deviceId) {
        GatewayClient.Response r = get(ports, trustFile, "/api/v1/devices/challenge?device_id=" + deviceId);
        if (r.status() != 200) {
            throw new IllegalStateException("challenge " + r.status() + " " + r.body());
        }
        Map<String, Object> m = json(r.body());
        return new Challenge(((Number) m.get("issued_at_ms")).longValue(),
                Base64.getDecoder().decode((String) m.get("random_nonce_b64")), (String) m.get("hmac_tag_b64"));
    }

    /** The device's DEK private key from its simulator key partition. */
    public static PrivateKey dek(SpineFixture.Device d) {
        return d.sim().store().loadDek().orElseThrow().getPrivate();
    }

    /** A correct body for {@code deviceId} presenting {@code bootEpoch}, signed by {@code dekKey}, CSR for newKey. */
    public static Map<String, Object> body(String deviceId, Challenge ch, long bootEpoch, KeyPair newKey,
                                           PrivateKey dekKey) {
        return Simulator.reEnrollBody(deviceId, ch.issuedAtMs(), ch.nonce(), ch.tagB64(), bootEpoch,
                CsrFactory.create(newKey, deviceId), dekKey);
    }

    public static Map<String, Object> body(SpineFixture.Device d, Challenge ch, long bootEpoch) {
        return body(d.deviceId(), ch, bootEpoch, EcKeys.generateP256(), dek(d));
    }

    public static GatewayClient.Response post(TestPorts.Listeners ports, Path trustFile, Map<String, Object> body) {
        try (GatewayClient c = GatewayClient.publicClient(trustFile)) {
            return c.postJson(URI.create("https://127.0.0.1:" + ports.pub() + "/api/v1/devices/re-enroll"),
                    JSONObjectUtils.toJSONString(body));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    public static GatewayClient.Response get(TestPorts.Listeners ports, Path trustFile, String path) {
        try (GatewayClient c = GatewayClient.publicClient(trustFile)) {
            return c.get(URI.create("https://127.0.0.1:" + ports.pub() + path));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    public static String error(GatewayClient.Response r) {
        Object e = json(r.body()).get("error");
        return e == null ? null : e.toString();
    }

    public static Map<String, Object> json(String body) {
        try {
            return JSONObjectUtils.parse(body);
        } catch (ParseException e) {
            throw new IllegalStateException(body, e);
        }
    }
}
