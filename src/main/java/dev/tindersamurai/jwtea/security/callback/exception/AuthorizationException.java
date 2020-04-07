package dev.tindersamurai.jwtea.security.callback.exception;

public class AuthorizationException extends Exception {
	public AuthorizationException(String msg) {
		super("Authorization denied: " + msg);
	}
	public AuthorizationException(String msg, Throwable t) {
		super("Authorization denied: " + msg, t);
	}
}
