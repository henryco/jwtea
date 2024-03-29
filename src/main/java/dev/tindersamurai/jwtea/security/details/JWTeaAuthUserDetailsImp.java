package dev.tindersamurai.jwtea.security.details;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Collection;

public class JWTeaAuthUserDetailsImp implements JWTeaAuthUserDetails {

	private @Getter final String username;
	private @Getter final String audience;
	private final String[] authorities;
	private final boolean locked;

	public JWTeaAuthUserDetailsImp(String username, boolean locked, String ... authorities) {
		this("any", username, locked, authorities);
	}

	public JWTeaAuthUserDetailsImp(String audience, String username, boolean locked, String ... authorities) {
		this.authorities = authorities;
		this.audience = audience;
		this.username = username;
		this.locked = locked;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return AuthorityUtils.createAuthorityList(authorities);
	}

	@Override
	public boolean isAccountNonLocked() {
		return !locked;
	}

}
