package com.vitalsshield.server.gateway;

import com.vitalsshield.server.pki.CrlService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/** The CRL Distribution Point URLs already written into certificates. Public port only. */
@RestController
public class PkiCrlController {

    static final MediaType PEM_TEXT = MediaType.parseMediaType("text/plain;charset=US-ASCII");

    private final CrlService crls;

    public PkiCrlController(CrlService crls) {
        this.crls = crls;
    }

    @GetMapping("/api/v1/pki/intermediate-crl.pem")
    public Mono<ResponseEntity<String>> intermediateCrl() {
        return Mono.fromCallable(crls::intermediateCrlPem)
                .subscribeOn(Schedulers.boundedElastic())
                .map(pem -> ResponseEntity.ok().contentType(PEM_TEXT).body(pem));
    }

    @GetMapping("/api/v1/pki/root-crl.pem")
    public Mono<ResponseEntity<String>> rootCrl() {
        return Mono.fromCallable(crls::rootCrlPem)
                .subscribeOn(Schedulers.boundedElastic())
                .map(pem -> ResponseEntity.ok().contentType(PEM_TEXT).body(pem));
    }
}
