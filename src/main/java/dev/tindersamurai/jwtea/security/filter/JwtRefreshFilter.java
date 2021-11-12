package dev.tindersamurai.jwtea.security.filter;

import dev.tindersamurai.jwtea.security.callback.RefreshTokenCallback;
import dev.tindersamurai.jwtea.security.callback.data.HttpServlet;
import dev.tindersamurai.jwtea.security.callback.data.Token;
import dev.tindersamurai.jwtea.security.props.JwtSecretProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class JwtRefreshFilter extends OncePerRequestFilter {

	private final JwtSecretProperties jwtSecretProperties;
	private @Setter
    RefreshTokenCallback refreshTokenCallback;
	private RequestMatcher requestMatcher;

	public JwtRefreshFilter(
			JwtSecretProperties jwtSecretProperties,
			RefreshTokenCallback refreshTokenCallback,
			String refreshUrl
	) {
		this(jwtSecretProperties, refreshUrl);
		this.refreshTokenCallback = refreshTokenCallback;
	}

	public JwtRefreshFilter(
			JwtSecretProperties jwtSecretProperties,
			String refreshUrl
	) {
		this.jwtSecretProperties = jwtSecretProperties;
		this.setFilterProcessesUrl(refreshUrl);
	}

	private void setRequestMatcher(
			RequestMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		this.requestMatcher = requestMatcher;
	}

	private void setFilterProcessesUrl(String filterProcessesUrl) {
		setRequestMatcher(new AntPathRequestMatcher(filterProcessesUrl));
	}

	@SuppressWarnings("unchecked")
	private Map<String, Object> extractClaims(Claims body) {
		try {
			val map = body.get("extra", Map.class);
			if (map == null)
				return Collections.emptyMap();
			return ((Map<String, Object>) map);
		} catch (Exception e) {
			log.warn("cannot parse claims");
			return Collections.emptyMap();
		}
	}

	@Override
	protected void doFilterInternal(
			HttpServletRequest request,
			HttpServletResponse response,
			FilterChain filterChain
	) throws ServletException, IOException {
		if (!requestMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		log.debug("jwt refresh filter: {}, {}, {}", request, response, filterChain);

		val signingKey = jwtSecretProperties.getJwtSecretKey().getBytes();
		val servlet = new HttpServlet(request, response);

		String token = request.getHeader(jwtSecretProperties.getJwtTokenHeader());
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

		if (token == null || token.isEmpty() ||
				!(token.startsWith(jwtSecretProperties.getJwtTokenPrefix()) || jwtSecretProperties.isCookieEnabled())
		)
			throw new IllegalArgumentException("Token not present");

		try {
			val parsed = Jwts.parser().setSigningKey(signingKey)
					.parseClaimsJws(token.replace(jwtSecretProperties.getJwtTokenPrefix(), ""));
			val body = parsed.getBody();
			val expiration = body.getExpiration();
			val username = body.getSubject();
			val tokenId = body.getId();
			val audience = body.getAudience();
			val claims = extractClaims(body);

			val tokenData = new Token(audience, username, tokenId, expiration, token, claims);

			if (refreshTokenCallback != null)
				refreshTokenCallback.preRefresh(tokenData, servlet);

			val newTokenId = UUID.randomUUID().toString();
			val newExpTime = createExpTime();

			val roles = ((List<?>) body.get("role")).stream().map(Object::toString).collect(Collectors.toList());
			val newToken = Jwts.builder()
					.signWith(Keys.hmacShaKeyFor(signingKey), SignatureAlgorithm.HS512)
					.setHeaderParam("type", jwtSecretProperties.getJwtTokenType())
					.setIssuer(jwtSecretProperties.getJwtTokenIssuer())
					.setAudience(audience)
					.setExpiration(newExpTime)
					.setId(newTokenId)
					.claim("role", roles)
					.addClaims(claims)
					.setSubject(username)
					.compact();

			val newTokenData = new Token(audience, username, newTokenId, newExpTime, newToken, claims);

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

		} catch (Exception e) {
			throw new RuntimeException("Cannot parse or process jwt token", e);
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
