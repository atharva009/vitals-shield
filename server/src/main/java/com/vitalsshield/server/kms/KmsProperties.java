package com.vitalsshield.server.kms;

import java.net.URI;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * KMS client settings ({@code vitalsshield.kms.*}).
 *
 * @param endpoint        optional endpoint override (LocalStack in the {@code local} profile); null means real AWS
 * @param region          AWS region, required
 * @param accessKeyId     optional static access key; when absent the default AWS credentials chain is used
 * @param secretAccessKey optional static secret key, paired with {@code accessKeyId}
 */
@ConfigurationProperties("vitalsshield.kms")
public record KmsProperties(URI endpoint, String region, String accessKeyId, String secretAccessKey) {
}
