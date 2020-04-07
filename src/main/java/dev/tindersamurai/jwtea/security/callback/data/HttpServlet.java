package dev.tindersamurai.jwtea.security.callback.data;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Value;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Value @Builder
@AllArgsConstructor
public class HttpServlet {
	private HttpServletRequest request;
	private HttpServletResponse response;
}
