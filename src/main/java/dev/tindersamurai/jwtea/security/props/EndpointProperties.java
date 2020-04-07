package dev.tindersamurai.jwtea.security.props;

import lombok.*;

@Value @AllArgsConstructor @Builder
public class EndpointProperties {
    private String[] secured;
    private String[] open;
}
