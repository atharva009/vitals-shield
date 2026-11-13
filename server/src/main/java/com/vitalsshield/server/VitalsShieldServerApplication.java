package com.vitalsshield.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class VitalsShieldServerApplication {

    /** Disables stateless TLS session tickets in the JDK server. Must be set before any JSSE class initializes. */
    public static final String SESSION_TICKET_PROPERTY = "jdk.tls.server.enableSessionTicketExtension";

    public static void main(String[] args) {
        System.setProperty(SESSION_TICKET_PROPERTY, "false");
        SpringApplication.run(VitalsShieldServerApplication.class, args);
    }
}
