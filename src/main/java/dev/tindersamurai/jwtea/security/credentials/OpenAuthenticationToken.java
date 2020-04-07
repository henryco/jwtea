package dev.tindersamurai.jwtea.security.credentials;

import lombok.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.util.Collections;

public class OpenAuthenticationToken extends AbstractAuthenticationToken {

	private final String code;

	public OpenAuthenticationToken(@NonNull String code) {
		super(Collections.emptyList());
		this.code = code;
	}

	@Override
	public Object getCredentials() {
		return null;
	}

	@Override
	public Object getPrincipal() {
		return code;
	}
}
