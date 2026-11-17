package com.vitalsshield.server.pki;

import java.nio.file.Path;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * PKI settings ({@code vitalsshield.pki.*}).
 *
 * @param publicBaseUrl         base for CRL Distribution Point URLs
 * @param allowHierarchyRebuild true only in the local profile: lets reconciliation regenerate CA keys
 * @param trustFile             where the current Root CA PEM is published after reconciliation
 * @param leafTtl               device leaf validity (DECISIONS #83: PT12H by default, PT4M in the local profile)
 * @param gatewayLeafTtl        default gateway TLS leaf validity
 * @param renewalGrace          how long a RENEWED certificate keeps working after its successor's first use (Protocol B)
 */
@ConfigurationProperties("vitalsshield.pki")
public record PkiProperties(
        @DefaultValue("https://localhost:8444") String publicBaseUrl,
        @DefaultValue("false") boolean allowHierarchyRebuild,
        @DefaultValue("var/trust/root-ca.pem") Path trustFile,
        @DefaultValue("PT12H") Duration leafTtl,
        @DefaultValue("PT24H") Duration gatewayLeafTtl,
        @DefaultValue("PT60S") Duration renewalGrace) {
}
