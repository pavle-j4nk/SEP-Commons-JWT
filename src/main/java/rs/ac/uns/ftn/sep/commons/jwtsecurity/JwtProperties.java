package rs.ac.uns.ftn.sep.commons.jwtsecurity;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@EnableConfigurationProperties({JwtProperties.class})
@ConfigurationProperties(prefix = "jwt", ignoreUnknownFields = false)
public class JwtProperties {

    /**
     * Token duration in milliseconds.
     */
    private Integer durationMillis = 3_600_000;

    /**
     * Singing key alias in keystore.
     */
    private String signingKey = "authentication";
}
