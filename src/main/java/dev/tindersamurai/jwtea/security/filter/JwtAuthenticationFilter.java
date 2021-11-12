package dev.tindersamurai.jwtea.security.filter;

import dev.tindersamurai.jwtea.security.auth.AuthenticationProcessor;
import dev.tindersamurai.jwtea.security.callback.AuthenticationCallback;
import dev.tindersamurai.jwtea.security.callback.data.HttpServlet;
import dev.tindersamurai.jwtea.security.callback.data.Token;
import dev.tindersamurai.jwtea.security.details.JWTeaAuthUserDetails;
import dev.tindersamurai.jwtea.security.props.JwtSecretProperties;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private final AuthenticationProcessor authenticationProcessor;
	private final JwtSecretProperties jwtSecretProperties;
	private @Setter AuthenticationCallback authenticationCallback;

	public JwtAuthenticationFilter(
			AuthenticationProcessor authenticationProcessor,
			JwtSecretProperties jwtSecretProperties,
			AuthenticationCallback authenticationCallback,
			String filterProcessUrl
	) {
		this(authenticationProcessor, jwtSecretProperties, filterProcessUrl);
		this.authenticationCallback = authenticationCallback;
	}

	public JwtAuthenticationFilter(
			AuthenticationProcessor authenticationProcessor,
			JwtSecretProperties jwtSecretProperties,
			String filterProcessUrl
	) {
		this.jwtSecretProperties = jwtSecretProperties;
		this.authenticationProcessor = authenticationProcessor;
		setAuthenticationManager(authenticationProcessor.getAuthenticationManager());
		setFilterProcessesUrl(filterProcessUrl);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
		return authenticationProcessor.attemptAuthentication(request, response);
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
											FilterChain filterChain, Authentication authentication) {
		log.debug(
				"successfulAuthentication: {}, {}, {}, {}",
				request, response, filterChain, authentication
		);

		val servlet = new HttpServlet(request, response);
		val user = ((JWTeaAuthUserDetails) authentication.getPrincipal());
		val roles = user.getAuthorities()
				.stream()
				.map(GrantedAuthority::getAuthority)
				.collect(Collectors.toList());

		val signingKey = jwtSecretProperties.getJwtSecretKey().getBytes();

		Token tokenData = new Token(
				user.getUsername(),
				user.getAudience(),
				UUID.randomUUID().toString(),
				createExpTime(),
				null,
				new HashMap<>()
		);

		if (authenticationCallback != null) {
			val data = authenticationCallback.preAuthentication(new Token(
					tokenData.getUserId(),
					tokenData.getAudience(),
					tokenData.getTokenId(),
					tokenData.getExpires(),
					tokenData.getJwt(),
					tokenData.getClaims()
			), servlet);
			if (data != null)
				tokenData = data;
		}

		val claims = new HashMap<String, Object>(); {
			claims.put("extra", tokenData.getClaims());
		}

		val token = Jwts.builder()
				.signWith(Keys.hmacShaKeyFor(signingKey), SignatureAlgorithm.HS512)
				.setHeaderParam("type", jwtSecretProperties.getJwtTokenType())
				.setIssuer(jwtSecretProperties.getJwtTokenIssuer())
				.setAudience(tokenData.getAudience())
				.setExpiration(tokenData.getExpires())
				.setSubject(user.getUsername())
				.setId(tokenData.getTokenId())
				.claim("role", roles)
				.addClaims(claims)
				.compact();

		val newTokenData = new Token(
				tokenData.getUserId(),
				tokenData.getAudience(),
				tokenData.getTokenId(),
				tokenData.getExpires(),
				token,
				tokenData.getClaims()
		);

		response.addHeader(
				jwtSecretProperties.getJwtTokenHeader(),
				jwtSecretProperties.getJwtTokenPrefix() + token
		);

		response.addDateHeader(
				jwtSecretProperties.getJwtExpireHeader(),
				tokenData.getExpires().getTime()
		);

		response.addHeader(
				jwtSecretProperties.getJwtExpireEpochHeader(),
				Long.toString(tokenData.getExpires().getTime())
		);

		if (jwtSecretProperties.isCookieEnabled()) {
			val cookie = new Cookie(
					jwtSecretProperties.getJwtTokenHeader(),
					token
			);

			val maxAge = (!jwtSecretProperties.isCookieSession())
					? getTokenLiveTimeSec(newTokenData.getExpires())
					: -1;
			cookie.setHttpOnly(jwtSecretProperties.isCookieHttpOnly());
			cookie.setSecure(jwtSecretProperties.isCookieSecure());
			cookie.setPath(jwtSecretProperties.getCookiePath());
			cookie.setMaxAge(maxAge);

			val domain = jwtSecretProperties.getCookieDomain();
			if (domain != null) {
				cookie.setDomain(domain);
			}

			response.addCookie(cookie);
		}

		if (authenticationCallback != null) {
			authenticationCallback.postAuthentication(newTokenData, servlet);
		}
	}

	private Date createExpTime() {
		val now = System.currentTimeMillis();
		return new Date(now + jwtSecretProperties.getJwtTokenLiveTime());
	}

	private int getTokenLiveTimeSec(Date expires) {
		val now = Calendar.getInstance().getTime().getTime();
		return (int) ((expires.getTime() - now) / 1000);
	}
}
