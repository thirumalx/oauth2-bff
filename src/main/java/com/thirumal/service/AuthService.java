package com.thirumal.service;

import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
/**
 * @author ThirumalM
 */
@Service
public class AuthService {
	
	Logger logger = LoggerFactory.getLogger(AuthService.class);

	private final ClientRegistrationRepository repo;
	
	public AuthService(ClientRegistrationRepository repo) {
		this.repo = repo;
	}


    public String buildAuthorizationUri(String state, String baseUrl) {

        ClientRegistration reg = repo.findByRegistrationId("bff-client-oidc");

        // Resolve redirectUri
        String redirectUri = reg.getRedirectUri()
                .replace("{baseUrl}", baseUrl)
                .replace("{registrationId}", reg.getRegistrationId());

        // Resolve scopes
        String scopes = reg.getScopes().stream()
                .collect(Collectors.joining(" "));

        return UriComponentsBuilder
                .fromUriString(reg.getProviderDetails().getAuthorizationUri())
                .queryParam("response_type", "code")
                .queryParam("client_id", reg.getClientId())
                .queryParam("redirect_uri", redirectUri)
                .queryParam("scope", scopes)
                .queryParam("state", state)
                .encode()
                .build()
                .toUriString();
    }

}
