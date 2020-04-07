package dev.tindersamurai.jwtea.security.filter;

import dev.tindersamurai.jwtea.security.callback.DisAuthenticationCallback;
import dev.tindersamurai.jwtea.security.callback.data.HttpServlet;
import dev.tindersamurai.jwtea.security.callback.data.Token;
import dev.tindersamurai.jwtea.security.props.JwtSecretProperties;
import io.jsonwebtoken.Jwts;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.lang.NonNull;
import org.springframework.security.core.context.SecurityContextHolder;
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

@Slf4j
public class JwtLogoutFilter extends OncePerRequestFilter {

	private final JwtSecretProperties jwtSecretProperties;
	private @Setter
    DisAuthenticationCallback disAuthenticationCallback;
	private RequestMatcher requestMatcher;

	public JwtLogoutFilter(
			JwtSecretProperties jwtSecretProperties,
			DisAuthenticationCallback disAuthenticationCallback,
			String logoutUrl
	) {
		this(jwtSecretProperties, logoutUrl);
		this.disAuthenticationCallback = disAuthenticationCallback;
	}

	public JwtLogoutFilter(
			JwtSecretProperties jwtSecretProperties,
			String logoutUrl
	) {
		this.jwtSecretProperties = jwtSecretProperties;
		this.setFilterProcessesUrl(logoutUrl);
	}

	private void setRequestMatcher(
			RequestMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		this.requestMatcher = requestMatcher;
	}

	private void setFilterProcessesUrl(String filterProcessesUrl) {
		setRequestMatcher(new AntPathRequestMatcher(filterProcessesUrl));
	}

	@Override
	protected void doFilterInternal(
			@NonNull HttpServletRequest request,
			@NonNull HttpServletResponse response,
			@NonNull FilterChain filterChain
	) throws ServletException, IOException {
		if (!requestMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		log.debug("jwt logout filter: {}, {}, {}", request, response, filterChain);
		removeTokenFromWhitelist(request, response);

		SecurityContextHolder.getContext().setAuthentication(null);
		response.setStatus(200);
	}

	private void removeTokenFromWhitelist(HttpServletRequest request, HttpServletResponse response) {

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

		if (token != null && !token.isEmpty() &&
				(token.startsWith(jwtSecretProperties.getJwtTokenPrefix()) || jwtSecretProperties.isCookieEnabled())
		) {
			try {
				val signingKey = jwtSecretProperties.getJwtSecretKey().getBytes();
				val parsedToken = Jwts.parser()
						.setSigningKey(signingKey)
						.parseClaimsJws(token.replace(jwtSecretProperties.getJwtTokenPrefix(), ""));

				if (jwtSecretProperties.isCookieEnabled() && request.getCookies() != null) {
					val cookie = new Cookie(jwtSecretProperties.getJwtTokenHeader(), "0");
					cookie.setMaxAge(0);
					cookie.setHttpOnly(jwtSecretProperties.isCookieHttpOnly());
					cookie.setSecure(jwtSecretProperties.isCookieSecure());
					cookie.setPath(jwtSecretProperties.getCookiePath());
					response.addCookie(cookie);
				}

				if (disAuthenticationCallback != null) {
					disAuthenticationCallback.disAuthenticate(new Token(
							parsedToken.getBody().getSubject(),
							parsedToken.getBody().getId(),
							parsedToken.getBody().getExpiration(),
							token
					), new HttpServlet(request, response));
				}
			} catch (Exception e) {
				log.warn("Cannot parse or process jwt token", e);
			}
		}
	}

}
