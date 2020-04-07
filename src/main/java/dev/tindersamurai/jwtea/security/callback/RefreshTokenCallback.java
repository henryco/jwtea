package dev.tindersamurai.jwtea.security.callback;

import dev.tindersamurai.jwtea.security.callback.data.HttpServlet;
import dev.tindersamurai.jwtea.security.callback.data.Token;
import dev.tindersamurai.jwtea.security.callback.exception.AuthorizationException;

public interface RefreshTokenCallback {

	default void preRefresh(Token token, HttpServlet servlet) throws AuthorizationException {
		// nothing
	}

	void postRefresh(Token token, HttpServlet servlet) throws AuthorizationException;

}
