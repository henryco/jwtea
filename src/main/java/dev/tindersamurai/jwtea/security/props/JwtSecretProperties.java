package dev.tindersamurai.jwtea.security.props;

public interface JwtSecretProperties {

	String getJwtSecretKey();

	String getLoginEndpoint();

	String getLogoutEndpoint();

	String getRefreshEndpoint();

	String getRedirectEndpoint();

	String getJwtTokenIssuer();

	String getJwtTokenAudience();

	long getJwtTokenLiveTime();

	long getRefreshFrameTime();

	boolean isCookieEnabled();

	boolean isCookieSecure();

	boolean isCookieHttpOnly();

	boolean isCookieSession();

	boolean isAutoRefresh();

	String getCookieDomain();

	String getCookiePath();

	default String getJwtTokenHeader() {
		return "Authorization";
	}

	default String getJwtExpireHeader() {
		return "Auth-expired-date";
	}

	default String getJwtExpireEpochHeader() {
		return "Auth-expired-epoch";
	}

	default String getJwtTokenPrefix() {
		return "Bearer ";
	}

	default String getJwtTokenType() {
		return "JWT";
	}

    String[] getOpenEndpoints();

	String[] getProtectedEndpoints();
}
