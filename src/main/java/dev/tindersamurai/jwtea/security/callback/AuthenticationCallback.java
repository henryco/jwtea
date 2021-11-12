package dev.tindersamurai.jwtea.security.callback;

import dev.tindersamurai.jwtea.security.callback.data.HttpServlet;
import dev.tindersamurai.jwtea.security.callback.data.Token;

public interface AuthenticationCallback {

	default Token preAuthentication(Token token, HttpServlet servlet) {
		return token;
	}

	void postAuthentication(Token token, HttpServlet servlet);


}
