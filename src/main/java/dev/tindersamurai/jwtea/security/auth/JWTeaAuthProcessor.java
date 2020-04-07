package dev.tindersamurai.jwtea.security.auth;

import dev.tindersamurai.jwtea.security.credentials.OpenAuthenticationToken;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Slf4j
public class JWTeaAuthProcessor implements AuthenticationProcessor {

	private final @Getter AuthenticationManager authenticationManager;

	public JWTeaAuthProcessor(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
		log.debug("attemptAuthentication: {}, {}", request, response);
		val code = request.getParameter("code");
		return authenticationManager.authenticate(new OpenAuthenticationToken(code));
	}
}
