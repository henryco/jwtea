package dev.tindersamurai.jwtea.security.credentials;

import lombok.Value;

@Value public class TokenBasedPrincipal {
	private String tokenId;
	private String userId;
	private long expires;
}
