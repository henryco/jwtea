package dev.tindersamurai.jwtea;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data @ConfigurationProperties(prefix = "dev.tindersamurai.jwtea")
public class JWTeaConfigProperties {

	@Data public static class Endpoint {
		private String redirect;
		private String refresh;
		private String logout;
		private String login;

		private String[] secured;
		private String[] open;
	}

	@Data public static class Cookies {
		private Boolean httpOnly;
		private Boolean enabled;
		private Boolean session;
		private Boolean secure;
		private String domain;
		private String path;
	}

	@Data public static class Refresh {
		private Boolean enabled;
		private Long frame;
	}

	private Endpoint endpoint;
	private Cookies cookies;
	private Refresh refresh;
	private String audience;
	private String secret;
	private String issuer;
	private Long expires;
}
