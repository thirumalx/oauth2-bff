package com.thirumal.service;

import java.net.URI;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

@Service
public class AuthService {

    @Value("${auth.server.base-url}")
    private String authBase;

    @Value("${auth.client.id}")
    private String clientId;

    @Value("${auth.client.secret}")
    private String clientSecret;

    @Value("${auth.redirect-uri}")
    private String redirectUri;

    private final RestTemplate rest = new RestTemplate();

    public String buildAuthorizationUri(String state) {
        StringBuilder sb = new StringBuilder();
        sb.append(authBase);
        if (!authBase.endsWith("/")) {
            sb.append("/");
        }
        sb.append("oauth2/authorize");
        sb.append("?response_type=code");
        sb.append("&client_id=").append(clientId);
        sb.append("&scope=openid%20profile%20email");
        sb.append("&redirect_uri=").append(encode(redirectUri));
        if (state != null && !state.isBlank()) {
            sb.append("&state=").append(encode(state));
        }
        return sb.toString();
    }

    public TokenResponse exchangeCode(String code) {
        String tokenUrl = join(authBase, "oauth2/token");
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "authorization_code");
        form.add("code", code);
        form.add("redirect_uri", redirectUri);
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);

        ResponseEntity<TokenResponse> resp = rest.postForEntity(URI.create(tokenUrl), request, TokenResponse.class);
        return resp.getBody();
    }

    public TokenResponse refresh(String refreshToken) {
        String tokenUrl = join(authBase, "oauth2/token");
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "refresh_token");
        form.add("refresh_token", refreshToken);
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);
        ResponseEntity<TokenResponse> resp = rest.postForEntity(URI.create(tokenUrl), request, TokenResponse.class);
        return resp.getBody();
    }

    public Map<String, Object> userInfo(String accessToken) {
        String userUrl = join(authBase, "userinfo");
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        headers.setAccept(java.util.List.of(MediaType.APPLICATION_JSON));
        HttpEntity<Void> req = new HttpEntity<>(headers);
        ResponseEntity<Map> resp = rest.postForEntity(URI.create(userUrl), req, Map.class);
        return resp.getBody();
    }

    public void revoke(String token, String tokenTypeHint) {
        String revokeUrl = join(authBase, "oauth2/revoke");
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("token", token);
        form.add("token_type_hint", tokenTypeHint);
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);
        rest.postForEntity(URI.create(revokeUrl), request, Void.class);
    }

    private static String join(String base, String path) {
        StringBuilder sb = new StringBuilder();
        sb.append(base);
        if (!base.endsWith("/")) {
            sb.append("/");
        }
        sb.append(path);
        return sb.toString();
    }

    private static String encode(String s) {
        return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8);
    }

}
