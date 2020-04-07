package dev.tindersamurai.jwtea.security.service;

import dev.tindersamurai.jwtea.security.details.JWTeaAuthUserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public interface JWTeaAuthDetailsService {

	final class InvalidCodeException extends UsernameNotFoundException {
		public InvalidCodeException(String code) {
			super("Invalid auth code: " + code);
		}
	}

	JWTeaAuthUserDetails loadByAuthCode(String code) throws InvalidCodeException;

}
