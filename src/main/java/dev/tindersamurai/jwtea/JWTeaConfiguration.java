package dev.tindersamurai.jwtea;

import dev.tindersamurai.jwtea.security.ajax.AjaxAwareAuthEntryPoint;
import dev.tindersamurai.jwtea.security.auth.AuthenticationProcessor;
import dev.tindersamurai.jwtea.security.auth.JWTeaAuthManager;
import dev.tindersamurai.jwtea.security.auth.JWTeaAuthProcessor;
import dev.tindersamurai.jwtea.security.callback.AuthenticationCallback;
import dev.tindersamurai.jwtea.security.callback.DisAuthenticationCallback;
import dev.tindersamurai.jwtea.security.callback.RefreshTokenCallback;
import dev.tindersamurai.jwtea.security.filter.JwtAuthenticationFilter;
import dev.tindersamurai.jwtea.security.filter.JwtAuthorizationFilter;
import dev.tindersamurai.jwtea.security.filter.JwtLogoutFilter;
import dev.tindersamurai.jwtea.security.filter.JwtRefreshFilter;
import dev.tindersamurai.jwtea.security.props.EndpointProperties;
import dev.tindersamurai.jwtea.security.props.JwtSecretProperties;
import dev.tindersamurai.jwtea.security.props.YmlBasedJwtSecretProperties;
import dev.tindersamurai.jwtea.security.service.JWTeaAuthDetailsService;
import dev.tindersamurai.jwtea.security.callback.AuthorizationCallback;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@SuppressWarnings("WeakerAccess")
@Configuration @Slf4j
public abstract class JWTeaConfiguration {

	private @Autowired JWTeaConfigProperties properties;
	private @Autowired Environment environment;

	public AuthorizationCallback provideAuthorizationCallback() {
		return null;
	}

	public AuthenticationCallback provideAuthenticationCallback() {
		return null;
	}

	public DisAuthenticationCallback provideDisAuthenticationCallback() {
		return null;
	}

	public RefreshTokenCallback provideRefreshTokenCallback() {
		return null;
	}

	@NonNull public abstract JWTeaAuthDetailsService provideAuthDetailsService();

	@Bean
	public EndpointProperties provideEndpointProperties() {
		log.debug("provideEndpointProperties");
		val properties = provideJwtSecretProperties();
		return EndpointProperties.builder()
				.secured(properties.getProtectedEndpoints())
				.open(properties.getOpenEndpoints())
				.build();
	}

	@Bean
	public String provideLoginEndpoint() {
		log.debug("provideLoginEndpoint");
		return provideJwtSecretProperties().getLoginEndpoint();
	}

	@Bean
	public String provideLogoutEndpoint() {
		log.debug("provideLogoutEndpoint");
		return provideJwtSecretProperties().getLogoutEndpoint();
	}

	@Bean
	public String provideRefreshEndpoint() {
		log.debug("provideRefreshEndpoint");
		return provideJwtSecretProperties().getRefreshEndpoint();
	}

	@Bean
	public String provideRedirectEndpoint() {
		log.debug("provideRedirectEndpoint");
		return provideJwtSecretProperties().getRedirectEndpoint();
	}

	@Bean
	public JwtSecretProperties provideJwtSecretProperties() {
		log.debug("provideJwtSecretProperties");
		return new YmlBasedJwtSecretProperties(properties, environment);
	}

	@Bean
	public AjaxAwareAuthEntryPoint provideAjaxAwareAuthEntryPoint() {
		log.debug("provideAjaxAwareAuthEntryPoint");
		return new AjaxAwareAuthEntryPoint(provideRedirectEndpoint());
	}

	@Bean @Order(Ordered.HIGHEST_PRECEDENCE)
	public AuthenticationManager provideAuthenticationManager() {
		log.debug("provideAuthenticationManager");
		return new JWTeaAuthManager(provideAuthDetailsService());
	}

	@Bean
	public FilterRegistrationBean<JwtLogoutFilter> logoutFilterRegistrationBean(
			JwtLogoutFilter jwtLogoutFilter
	) {
		log.debug("logoutFilterRegistrationBean: {}", jwtLogoutFilter);
		val registrationBean = new FilterRegistrationBean<JwtLogoutFilter>(); {
			registrationBean.setFilter(jwtLogoutFilter);
			registrationBean.setOrder(Ordered.HIGHEST_PRECEDENCE);
		}
		return registrationBean;
	}

	@Bean
	public FilterRegistrationBean<JwtRefreshFilter> refreshFilterRegistrationBean(
			JwtRefreshFilter jwtRefreshFilter
	) {
		log.debug("refreshFilterRegistrationBean: {}", jwtRefreshFilter);
		val registrationBean = new FilterRegistrationBean<JwtRefreshFilter>(); {
			registrationBean.setFilter(jwtRefreshFilter);
			registrationBean.setOrder(Ordered.HIGHEST_PRECEDENCE + 1);
		}
		return registrationBean;
	}

	@Bean
	public AuthenticationProcessor provideAuthenticationProcessor(
			AuthenticationManager authenticationManager
	) {
		log.debug("provideAuthenticationProcessor: {}", authenticationManager);
		return new JWTeaAuthProcessor(authenticationManager);
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		log.debug("corsConfigurationSource");
		val source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
		return source;
	}

	@Bean
	public AbstractAuthenticationProcessingFilter provideJwtAuthenticationFilter(
			AuthenticationProcessor authenticationProcessor,
			JwtSecretProperties jwtSecretProperties
	) {
		log.debug("provideJwtAuthenticationFilter: {}, {}", authenticationProcessor, jwtSecretProperties);
		return new JwtAuthenticationFilter(
				authenticationProcessor,
				jwtSecretProperties,
				provideAuthenticationCallback(),
				provideLoginEndpoint()
		);
	}

	@Bean
	public BasicAuthenticationFilter provideJwtAuthorizationFilter(
			AuthenticationManager authenticationManager,
			JwtSecretProperties jwtSecretProperties
	) {
		log.debug("provideJwtAuthorizationFilter: {}, {}", authenticationManager, jwtSecretProperties);
		return new JwtAuthorizationFilter(
				authenticationManager,
				jwtSecretProperties,
				provideAuthorizationCallback(),
				provideRefreshTokenCallback()
		);
	}

	@Bean
	public JwtLogoutFilter provideJwtLogoutFilter(
			JwtSecretProperties jwtSecretProperties
	) {
		log.debug("provideJwtLogoutFilter: {}", jwtSecretProperties);
		return new JwtLogoutFilter(
				jwtSecretProperties,
				provideDisAuthenticationCallback(),
				provideLogoutEndpoint()
		);
	}

	@Bean
	public JwtRefreshFilter provideJwtRefreshFilter(
			JwtSecretProperties jwtSecretProperties
	) {
		log.debug("provideJwtRefreshFilter");
		return new JwtRefreshFilter(
				jwtSecretProperties,
				provideRefreshTokenCallback(),
				provideRefreshEndpoint()
		);
	}
}
