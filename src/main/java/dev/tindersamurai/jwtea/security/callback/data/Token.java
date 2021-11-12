package dev.tindersamurai.jwtea.security.callback.data;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Value;

import java.io.Serializable;
import java.util.Date;
import java.util.Map;

@Value @Builder
@AllArgsConstructor
public class Token {
	private Serializable userId;
	private String audience;
	private String tokenId;
	private Date expires;
	private String jwt;
	private final Map<String, Object> claims;
}
