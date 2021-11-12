package dev.tindersamurai.jwtea.security.callback;

import dev.tindersamurai.jwtea.security.callback.data.HttpServlet;
import dev.tindersamurai.jwtea.security.callback.data.Token;
import dev.tindersamurai.jwtea.security.callback.exception.AuthorizationException;

public interface AuthorizationCallback {

	default Token preAuthorization(Token token, HttpServlet servlet) throws AuthorizationException {
		return token;
	}

	void postAuthorization(Token token, HttpServlet servlet) throws AuthorizationException ;
}
