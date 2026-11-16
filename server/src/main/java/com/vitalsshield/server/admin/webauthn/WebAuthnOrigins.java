package com.vitalsshield.server.admin.webauthn;

import java.util.Set;

/**
 * Relying party id and the origins whose clientDataJSON is accepted (DECISIONS #55). The RP id is "localhost": an IP
 * address cannot be an RP id, so the admin plane is reached as http://localhost:&lt;admin port&gt;.
 */
public record WebAuthnOrigins(String rpId, Set<String> origins) {

    public static final String RP_ID = "localhost";

    public static WebAuthnOrigins forAdminPort(int adminPort, boolean dashboardDevProxy) {
        return dashboardDevProxy
                ? new WebAuthnOrigins(RP_ID, Set.of("http://localhost:" + adminPort, "http://localhost:3000"))
                : new WebAuthnOrigins(RP_ID, Set.of("http://localhost:" + adminPort));
    }
}
