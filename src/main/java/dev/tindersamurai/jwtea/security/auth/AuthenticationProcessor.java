package dev.tindersamurai.jwtea.security.auth;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface AuthenticationProcessor {

	Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response);

	AuthenticationManager getAuthenticationManager();
}
