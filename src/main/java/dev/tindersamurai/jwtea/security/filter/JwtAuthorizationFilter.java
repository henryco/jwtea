package dev.tindersamurai.jwtea.security.filter;

import dev.tindersamurai.jwtea.security.callback.AuthorizationCallback;
import dev.tindersamurai.jwtea.security.callback.RefreshTokenCallback;
import dev.tindersamurai.jwtea.security.callback.data.HttpServlet;
import dev.tindersamurai.jwtea.security.callback.data.Token;
import dev.tindersamurai.jwtea.security.callback.exception.AuthorizationException;
import dev.tindersamurai.jwtea.security.credentials.TokenBasedPrincipal;
import dev.tindersamurai.jwtea.security.props.JwtSecretProperties;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

	private final JwtSecretProperties jwtSecretProperties;
	private @Setter
    AuthorizationCallback authorizationCallback;
	private @Setter
    RefreshTokenCallback refreshTokenCallback;

	public JwtAuthorizationFilter(
			AuthenticationManager authenticationManager,
			JwtSecretProperties jwtSecretProperties,
			AuthorizationCallback authorizationCallback,
			RefreshTokenCallback refreshTokenCallback
	) {
		this(authenticationManager, jwtSecretProperties);
		this.authorizationCallback = authorizationCallback;
		this.refreshTokenCallback = refreshTokenCallback;
	}

	public JwtAuthorizationFilter(
			AuthenticationManager authenticationManager,
			JwtSecretProperties jwtSecretProperties
	) {
		super(authenticationManager);
		this.jwtSecretProperties = jwtSecretProperties;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
									FilterChain filterChain) throws IOException, ServletException {
		log.debug("AUTHORIZE");
		val authentication = getAuthentication(request, response);
		log.debug("authentication: {}", authentication);
		if (authentication == null) {
			filterChain.doFilter(request, response);
			return;
		}

		log.debug("AUTHORIZE[SET]");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		filterChain.doFilter(request, response);
	}

	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request, HttpServletResponse response) {

		String token;
		token = request.getHeader(jwtSecretProperties.getJwtTokenHeader());

		if (jwtSecretProperties.isCookieEnabled() && request.getCookies() != null) {
			for (val cookie : request.getCookies()) {
				if (jwtSecretProperties.getJwtTokenHeader().toLowerCase().trim()
						.equals(cookie.getName().toLowerCase().trim())
				) {
					token = cookie.getValue();
					break;
				}
			}
		}

		val servlet = new HttpServlet(request, response);

		if (token != null && !token.isEmpty() &&
				(token.startsWith(jwtSecretProperties.getJwtTokenPrefix()) || jwtSecretProperties.isCookieEnabled())
		) {
			try {
				val signingKey = jwtSecretProperties.getJwtSecretKey().getBytes();

				val parsedToken = Jwts.parser()
						.setSigningKey(signingKey)
						.parseClaimsJws(token.replace(jwtSecretProperties.getJwtTokenPrefix(), ""));

				val expiration = parsedToken.getBody().getExpiration();
				val username = parsedToken.getBody().getSubject();
				val tokenId = parsedToken.getBody().getId();

				val tokenData = new Token(username, tokenId, expiration, token);

				if (authorizationCallback != null)
					authorizationCallback.preAuthorization(tokenData, servlet);

				val authorities = ((List<?>) parsedToken.getBody().get("role")).stream()
						.map(a -> new SimpleGrantedAuthority((String) a)).collect(Collectors.toList());

				val expirationTime = expiration.getTime();
				if (username != null && !username.isEmpty()) {
					val user = new TokenBasedPrincipal(tokenId, username, expirationTime);

					if (jwtSecretProperties.isAutoRefresh()) {
						val time = jwtSecretProperties.getRefreshFrameTime();
						val now = Calendar.getInstance().getTime().getTime();
						val dif = expirationTime - now;
						if (dif > 0 && dif < time) {

							val body = parsedToken.getBody();

							if (refreshTokenCallback != null)
								refreshTokenCallback.preRefresh(tokenData, servlet);

							val newTokenId = UUID.randomUUID().toString();
							val newExpTime = createExpTime();

							val roles = ((List<?>) body.get("role")).stream().map(Object::toString).collect(Collectors.toList());
							val newToken = Jwts.builder()
									.signWith(Keys.hmacShaKeyFor(signingKey), SignatureAlgorithm.HS512)
									.setHeaderParam("type", jwtSecretProperties.getJwtTokenType())
									.setIssuer(jwtSecretProperties.getJwtTokenIssuer())
									.setAudience(jwtSecretProperties.getJwtTokenAudience())
									.setExpiration(newExpTime)
									.setId(newTokenId)
									.claim("role", roles)
									.setSubject(username)
									.compact();

							val newTokenData = new Token(username, newTokenId, newExpTime, newToken);

							response.addHeader(
									jwtSecretProperties.getJwtTokenHeader(),
									jwtSecretProperties.getJwtTokenPrefix() + newToken
							);

							response.addDateHeader(
									jwtSecretProperties.getJwtExpireHeader(),
									newTokenData.getExpires().getTime()
							);

							response.addHeader(
									jwtSecretProperties.getJwtExpireEpochHeader(),
									Long.toString(newTokenData.getExpires().getTime())
							);

							if (jwtSecretProperties.isCookieEnabled()) {
								val cookie = new Cookie(
										jwtSecretProperties.getJwtTokenHeader(),
										newToken
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

							if (refreshTokenCallback != null)
								refreshTokenCallback.postRefresh(newTokenData, servlet);

							if (authorizationCallback != null)
								authorizationCallback.postAuthorization(newTokenData, servlet);

							val newUser = new TokenBasedPrincipal(tokenId, username, newTokenData.getExpires().getTime());
							return new UsernamePasswordAuthenticationToken(newUser, null, authorities);
						}
					}

					response.addDateHeader(
							jwtSecretProperties.getJwtExpireHeader(),
							tokenData.getExpires().getTime()
					);

					response.addHeader(
							jwtSecretProperties.getJwtExpireEpochHeader(),
							Long.toString(tokenData.getExpires().getTime())
					);

					if (authorizationCallback != null)
						authorizationCallback.postAuthorization(tokenData, servlet);

					return new UsernamePasswordAuthenticationToken(user, null, authorities);
				}
			} catch (ExpiredJwtException e) {
				log.warn("Request to parse expired JWT : {} failed : {}", token, e.getMessage());
			} catch (UnsupportedJwtException e) {
				log.warn("Request to parse unsupported JWT : {} failed : {}", token, e.getMessage());
			} catch (MalformedJwtException e) {
				log.warn("Request to parse invalid JWT : {} failed : {}", token, e.getMessage());
			} catch (SignatureException e) {
				log.warn("Request to parse JWT with invalid signature : {} failed : {}", token, e.getMessage());
			} catch (IllegalArgumentException e) {
				log.warn("Request to parse empty or null JWT : {} failed : {}", token, e.getMessage());
			} catch (AuthorizationException e) {
				log.warn("Authorization exception: {}, failed: {}", token, e.getMessage());
			}
		}

		return null;
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
