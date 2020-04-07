package dev.tindersamurai.jwtea.security.ajax;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class AjaxAwareAuthEntryPoint extends LoginUrlAuthenticationEntryPoint {

	public AjaxAwareAuthEntryPoint(final String loginFormUrl) {
		super(loginFormUrl);
	}

	@Override
	public void commence(final HttpServletRequest request, final HttpServletResponse response, final AuthenticationException authException)
			throws IOException, ServletException {
		log.debug("commence: {}, {}, {}", request, response, authException);
		if ("XMLHttpRequest".equals(request.getHeader("X-Requested-With")))
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
		else super.commence(request, response, authException);
	}
}
