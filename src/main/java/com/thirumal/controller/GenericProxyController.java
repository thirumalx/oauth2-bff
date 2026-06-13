package com.thirumal.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

@RestController
public class GenericProxyController {

    private final RestTemplate restTemplate = new RestTemplate();

    @RequestMapping("/api/**")
    public ResponseEntity<byte[]> proxy(HttpServletRequest request, 
        @RegisteredOAuth2AuthorizedClient("bff-client-oidc") OAuth2AuthorizedClient client) throws URISyntaxException, IOException {

        // Remove /api prefix and forward to resource server
        String path = request.getRequestURI().substring(4); 
        String queryString = request.getQueryString() != null ? "?" + request.getQueryString() : "";
        
        // Hardcoded API Gateway / Resource Server URL for now
        URI uri = new URI("http://localhost:8000" + path + queryString);

        HttpHeaders headers = new HttpHeaders();
        // Forward the OAuth2 Access Token!
        if (client != null && client.getAccessToken() != null) {
            headers.setBearerAuth(client.getAccessToken().getTokenValue());
        }

        // Read request body if present
        byte[] body = request.getInputStream().readAllBytes();

        HttpEntity<byte[]> httpEntity = new HttpEntity<>(body, headers);

        return restTemplate.exchange(uri, HttpMethod.valueOf(request.getMethod()), httpEntity, byte[].class);
    }
}
