package com.vitalsshield.server.enrollment;

/** A validated, decoded Protocol A request. Byte arrays are the decoded DER blobs. */
public record EnrollRequest(String deviceId, String bootstrapToken, byte[] dekSpkiDer, byte[] olkCsrDer,
                            byte[] dekProofSig) {
}
