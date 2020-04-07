package dev.tindersamurai.jwtea.security.callback;

import dev.tindersamurai.jwtea.security.callback.data.HttpServlet;
import dev.tindersamurai.jwtea.security.callback.data.Token;

public interface AuthenticationCallback {

	default void preAuthentication(Token token, HttpServlet servlet) {
		// nothing
	}

	void postAuthentication(Token token, HttpServlet servlet);


}
