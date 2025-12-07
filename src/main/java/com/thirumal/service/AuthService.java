package com.thirumal.service;

import java.util.stream.Collectors;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

@Service
public class AuthService {

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
        String scopes = reg.getScopes()
                .stream()
                .collect(Collectors.joining(" "));

        String authorizeUrl = UriComponentsBuilder
                .fromUriString(reg.getProviderDetails().getAuthorizationUri())
                .queryParam("response_type", "code")
                .queryParam("client_id", reg.getClientId())
                .queryParam("redirect_uri", redirectUri)
                .queryParam("scope", scopes)
                .queryParam("state", state)
                .build()
                .toUriString();

        return authorizeUrl;
    }

}
