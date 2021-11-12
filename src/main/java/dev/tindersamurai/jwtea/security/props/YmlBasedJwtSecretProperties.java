package dev.tindersamurai.jwtea.security.props;

import dev.tindersamurai.jwtea.JWTeaConfigProperties;
import org.springframework.core.env.Environment;

public class YmlBasedJwtSecretProperties implements JwtSecretProperties {

	private final JWTeaConfigProperties properties;
	private final Environment environment;

	public YmlBasedJwtSecretProperties(
			JWTeaConfigProperties properties,
			Environment environment
	) {
		this.environment = environment;
		this.properties = properties;
	}

	@Override
	public String getJwtSecretKey() {
		return environment.getRequiredProperty("dev.tindersamurai.jwtea.secret");
	}

	@Override
	public long getJwtTokenLiveTime() {
		return environment.getProperty("dev.tindersamurai.jwtea.expires", Long.class, 864000000L);
	}

	@Override
	public long getRefreshFrameTime() {
		return environment.getProperty("dev.tindersamurai.jwtea.refresh.frame", Long.class, 120000L);
	}

	@Override
	public String getJwtTokenIssuer() {
		return environment.getProperty("dev.tindersamurai.jwtea.issuer", "jwtea-app");
	}

	@Override
	public String getLoginEndpoint() {
		return environment.getRequiredProperty("dev.tindersamurai.jwtea.endpoint.login");
	}

	@Override
	public String getLogoutEndpoint() {
		return environment.getRequiredProperty("dev.tindersamurai.jwtea.endpoint.logout");
	}

	@Override
	public String getRefreshEndpoint() {
		return environment.getRequiredProperty("dev.tindersamurai.jwtea.endpoint.refresh");
	}

	@Override
	public String getRedirectEndpoint() {
		return environment.getRequiredProperty("dev.tindersamurai.jwtea.endpoint.redirect");
	}

	@Override
	public boolean isCookieEnabled() {
		return environment.getProperty("dev.tindersamurai.jwtea.cookies.enabled", Boolean.class, false);
	}

	@Override
	public boolean isCookieSecure() {
		return environment.getProperty("dev.tindersamurai.jwtea.cookies.secure", Boolean.class, false);
	}

	@Override
	public boolean isCookieHttpOnly() {
		return environment.getProperty("dev.tindersamurai.jwtea.cookies.httpOnly", Boolean.class, false);
	}

	@Override
	public boolean isCookieSession() {
		return environment.getProperty("dev.tindersamurai.jwtea.cookies.session", Boolean.class, false);
	}

	@Override
	public boolean isAutoRefresh() {
		return environment.getProperty("dev.tindersamurai.jwtea.refresh.enabled", Boolean.class, false);
	}

	@Override
	public String getCookiePath() {
		return environment.getProperty("dev.tindersamurai.jwtea.cookies.path", "/");
	}

	@Override
	public String getCookieDomain() {
		return environment.getProperty("dev.tindersamurai.jwtea.cookies.domain");
	}

	@Override
	public String[] getOpenEndpoints() {
		try {
			return properties.getEndpoint().getOpen();
		} catch (Exception e) {
			return new String[]{
					"/resources/**",
					"/actuator/**",
					"/static/**",
					"/"
			};
		}
	}

	@Override
	public String[] getProtectedEndpoints() {
		try {
			return properties.getEndpoint().getSecured();
		} catch (Exception e) {
			return new String[]{"/api/**"};
		}
	}
}
