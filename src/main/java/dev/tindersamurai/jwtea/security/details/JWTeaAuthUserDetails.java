package dev.tindersamurai.jwtea.security.details;

import org.springframework.security.core.userdetails.UserDetails;

public interface JWTeaAuthUserDetails extends UserDetails {

	default String getPassword() {
		return null;
	}

	default boolean isAccountNonExpired() {
		return true;
	}

	default boolean isCredentialsNonExpired() {
		return true;
	}

	default boolean isEnabled() {
		return true;
	}

	String getAudience();

}
