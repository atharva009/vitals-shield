package com.vitalsshield.server.kms;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import org.junit.jupiter.api.Test;

/** The KMS client must use the JDK URL connection stack; the SDK's Netty async client is excluded from the build. */
class NoNettyNioClientTest {

    @Test
    void nettyNioAsyncHttpClientIsNotOnClasspath() {
        assertThatExceptionOfType(ClassNotFoundException.class).isThrownBy(
                () -> Class.forName("software.amazon.awssdk.http.nio.netty.NettyNioAsyncHttpClient"));
    }

    @Test
    void apacheHttpClientIsNotOnClasspath() {
        assertThatExceptionOfType(ClassNotFoundException.class).isThrownBy(
                () -> Class.forName("software.amazon.awssdk.http.apache.ApacheHttpClient"));
    }
}
