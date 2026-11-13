package com.vitalsshield.server.kms;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsClientBuilder;

/**
 * Builds the synchronous {@link KmsClient} on the JDK {@code HttpURLConnection} stack. KMS calls are blocking and run
 * on {@code boundedElastic} or the boot thread, never on a Netty event loop (see {@link KmsSigner}).
 */
@Configuration(proxyBeanMethods = false)
public class KmsConfig {

    @Bean(destroyMethod = "close")
    public KmsClient kmsClient(KmsProperties props) {
        if (!StringUtils.hasText(props.region())) {
            throw new IllegalStateException("vitalsshield.kms.region must be set");
        }
        KmsClientBuilder builder = KmsClient.builder()
                .httpClient(UrlConnectionHttpClient.builder().build())
                .region(Region.of(props.region()))
                .credentialsProvider(credentials(props));
        if (props.endpoint() != null) {
            builder.endpointOverride(props.endpoint());
        }
        return builder.build();
    }

    private static AwsCredentialsProvider credentials(KmsProperties props) {
        boolean hasKey = StringUtils.hasText(props.accessKeyId());
        boolean hasSecret = StringUtils.hasText(props.secretAccessKey());
        if (hasKey != hasSecret) {
            throw new IllegalStateException(
                    "vitalsshield.kms.access-key-id and secret-access-key must be set together");
        }
        if (hasKey) {
            return StaticCredentialsProvider.create(
                    AwsBasicCredentials.create(props.accessKeyId(), props.secretAccessKey()));
        }
        return DefaultCredentialsProvider.builder().build();
    }
}
