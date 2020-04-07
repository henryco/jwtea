package dev.tindersamurai.jwtea.security;

import dev.tindersamurai.jwtea.security.ajax.AjaxAwareAuthEntryPoint;
import dev.tindersamurai.jwtea.security.props.EndpointProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration @EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter  {

	private final AbstractAuthenticationProcessingFilter jwtAuthenticationFilter;
	private final BasicAuthenticationFilter jwtAuthorizationFilter;
	private final AjaxAwareAuthEntryPoint ajaxAwareAuthEntryPoint;
	private final EndpointProperties endpointProperties;

	@Autowired
	public SecurityConfiguration(
			AbstractAuthenticationProcessingFilter jwtAuthenticationFilter,
			BasicAuthenticationFilter jwtAuthorizationFilter,
			AjaxAwareAuthEntryPoint ajaxAwareAuthEntryPoint,
			EndpointProperties endpointProperties
	) {
		this.ajaxAwareAuthEntryPoint = ajaxAwareAuthEntryPoint;
		this.jwtAuthenticationFilter = jwtAuthenticationFilter;
		this.jwtAuthorizationFilter = jwtAuthorizationFilter;
		this.endpointProperties = endpointProperties;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and()
				.csrf().disable()
				.exceptionHandling()
				.authenticationEntryPoint(ajaxAwareAuthEntryPoint)
				.and()
				.authorizeRequests()
//				.antMatchers("/api/protected/**").authenticated()
//				.antMatchers("/api/open/**").permitAll()
//				.antMatchers("/resources/**").permitAll()
//				.antMatchers("/actuator/**").permitAll()
//				.antMatchers("/static/**").permitAll()
//				.antMatchers("/").permitAll()
				.antMatchers(endpointProperties.getSecured()).authenticated()
				.antMatchers(endpointProperties.getOpen()).permitAll()
				.and()
				.addFilter(jwtAuthenticationFilter)
				.addFilter(jwtAuthorizationFilter)
		;
	}

}
