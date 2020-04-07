package dev.tindersamurai.jwtea;

import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

/**
 * @author henrycodev@gmail.com
 */

@Configuration @ComponentScan @ConditionalOnBean(JWTeaConfiguration.class)
@EnableConfigurationProperties(JWTeaConfigProperties.class)
public class JWTeaAutoConfiguration {

}
