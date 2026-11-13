package com.vitalsshield.server.gateway;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.config.EnableWebFlux;

/**
 * WebFlux infrastructure (DispatcherHandler as the "webHandler" bean, codecs, handler mappings). Boot's WebFlux
 * auto-configuration is off because web-application-type is none; ListenerManager builds the HttpHandler itself.
 */
@Configuration(proxyBeanMethods = false)
@EnableWebFlux
public class WebFluxConfig {
}
