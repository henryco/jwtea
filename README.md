# **JWTea** ☕
[![Maven Central](https://img.shields.io/maven-central/v/dev.tindersamurai/jwtea?style=for-the-badge)](https://search.maven.org/artifact/dev.tindersamurai/jwtea)
[![GitHub](https://img.shields.io/github/license/henryco/jwtea?color=brown&style=for-the-badge)](https://github.com/henryco/jwtea/blob/master/LICENSE)

Easy jwt auth for spring security.

### Installation: 
Add dependency to your `pom.xml`
```xml
<dependency>
    <groupId>dev.tindersamurai</groupId>
    <artifactId>jwtea</artifactId>
    <version>1.1.0</version>
</dependency>
```

## How  to use:
##### 1) Define jwt secret in application properties:
```yaml
dev:
  tindersamurai:
    jwtea: 
      secret: 'SECRET SHOULD BE AT LEAST 64 CHARS LONG'
```


##### 2) Extend `JWTeaConfiguration` configuration class:
```java
@Configuration
public class JwtConfiguration extends JWTeaConfiguration {

	@Override
	public @NonNull JWTeaAuthDetailsService provideAuthDetailsService() {
		log.debug("provideAuthDetailsService");
		return null; // SHOULD BE IMPLEMENTED
	}

	@Override
	public @Nullable AuthorizationCallback provideAuthorizationCallback() {
		log.debug("provideAuthorizationCallback");
		return null; // optional, might be null
	}

	@Override
	public @Nullable AuthenticationCallback provideAuthenticationCallback() {
		log.debug("provideAuthenticationCallback");
		return null; // optional, might be null
	}

	@Override
	public @Nullable RefreshTokenCallback provideRefreshTokenCallback() {
		log.debug("provideRefreshTokenCallback");
		return null; // optional, might be null
	}

	@Override
	public @Nullable DisAuthenticationCallback provideDisAuthenticationCallback() {
		log.debug("provideDisAuthenticationCallback");
		return null; // optional, might be null
	}

	@Override // overrides application.yml
	public String provideLoginEndpoint() {
		return "/api/auth/login";
	}

	@Override // overrides application.yml
	public String provideLogoutEndpoint() {
		return "/api/auth/logout";
	}

	@Override // overrides application.yml
	public String provideRedirectEndpoint() {
		return "/#/unauthorized";
	}

	@Override // overrides application.yml
	public String provideRefreshEndpoint() {
		return "/api/auth/refresh";
	}
}
```

## Application properties definition:
```yaml
dev:
  tindersamurai:
    jwtea:
      endpoint:
        redirect: 'string'
        refresh: 'string'
        logout: 'string'
        login: 'string'
        open:
          - '/resources/**'
          - '/actuator/**'
          - '/static/**'
          - '/'
        secured:
          - '/api/**'
      cookies:
        httpOnly: 'boolean' # default: false
        session: 'boolean'  # default: false
        enabled: 'boolean'  # default: false
        secure: 'boolean'   # default: false
        domain: 'string'    # default: null
        path: 'string'      # default: '/'
      refresh:
        enabled: 'boolean'  # default: false
        frame: 'long'       # default: 120000
      secret: 'string'      # 64+ chars long
      issuer: 'string'      # optional
      expires: 'long'       # optional
      audience: 'string'    # optional
```

---
### Authorized Request:
Method: `ANY`  
Header: `Authorization: <JWT String>`  
___
### LOGIN Request:
Method: `POST`  
Header: `Content-type: application/x-www-form-urlencoded`  
Form-data: `code: <Your auth code here>` 
___
### LOGIN / REFRESH Response headers:
Authorization: `JWT String`  
Auth-expired-date: `Date`  
Auth-expired-epoch: `Long`
