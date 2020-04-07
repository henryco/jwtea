package dev.tindersamurai.jwtea.security.auth;

import dev.tindersamurai.jwtea.security.service.JWTeaAuthDetailsService;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.Objects;

@Slf4j
public class JWTeaAuthManager implements AuthenticationManager {

	private final JWTeaAuthDetailsService JWTeaAuthDetailsService;

	public JWTeaAuthManager(JWTeaAuthDetailsService JWTeaAuthDetailsService) {
		this.JWTeaAuthDetailsService = JWTeaAuthDetailsService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		log.debug("authenticate: {}", authentication);
		val tokenCode = Objects.toString(authentication.getPrincipal());
		val userDetails = JWTeaAuthDetailsService.loadByAuthCode(tokenCode);
		return new UsernamePasswordAuthenticationToken(userDetails, null);
	}
}
