package dev.tindersamurai.jwtea.security.callback.data;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Value;

import java.io.Serializable;
import java.util.Date;

@Value @Builder
@AllArgsConstructor
public class Token {
	private Serializable userId;
	private String tokenId;
	private Date expires;
	private String jwt;
}
