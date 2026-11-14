package com.vitalsshield.server.gateway;

import com.vitalsshield.server.pki.CrlService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/** The CRL Distribution Point URLs already written into certificates. Public port only. Serves the cache; never signs. */
@RestController
public class PkiCrlController {

    static final MediaType PEM_TEXT = MediaType.parseMediaType("text/plain;charset=US-ASCII");

    private final CrlService crls;

    public PkiCrlController(CrlService crls) {
        this.crls = crls;
    }

    @GetMapping("/api/v1/pki/intermediate-crl.pem")
    public Mono<ResponseEntity<String>> intermediateCrl() {
        return crls.currentIntermediateCrl()
                .map(pem -> ResponseEntity.ok().contentType(PEM_TEXT).body(pem));
    }

    @GetMapping("/api/v1/pki/root-crl.pem")
    public Mono<ResponseEntity<String>> rootCrl() {
        return crls.currentRootCrl()
                .map(pem -> ResponseEntity.ok().contentType(PEM_TEXT).body(pem));
    }
}
