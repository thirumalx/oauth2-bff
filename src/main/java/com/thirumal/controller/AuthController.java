package com.thirumal.controller;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import com.thirumal.service.AuthService;

import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/bff")
public class AuthController {

	private final AuthService authService;

	public AuthController(AuthService authService) {
		this.authService = authService;
	}

	@GetMapping("/login")
	public ResponseEntity<Void> login(
	        @RequestParam(required = false) String redirect,
	        HttpServletRequest request) {

	    String state = (redirect != null) ?
	            Base64.getUrlEncoder().encodeToString(redirect.getBytes(StandardCharsets.UTF_8)) : "";

	    // Compute base URL dynamically
	    String baseUrl = UriComponentsBuilder.fromUriString(request.getRequestURL().toString())
	            .replacePath(null)
	            .toUriString();

	    String authorizeUrl = authService.buildAuthorizationUri(state, baseUrl);

	    HttpHeaders headers = new HttpHeaders();
	    headers.setLocation(URI.create(authorizeUrl));

	    return ResponseEntity.status(302).headers(headers).build();
	}


//	@GetMapping("/callback")
//	public ResponseEntity<Void> callback(@RequestParam("code") String code, @RequestParam(value = "state", required = false) String state) {
//		TokenResponse tokens = authService.exchangeCode(code);
//
//		// set cookies for access_token and refresh_token
//		ResponseCookie accessCookie = ResponseCookie.from("access_token", tokens.getAccessToken())
//				.httpOnly(true)
//				.path("/")
//				.maxAge(tokens.getExpiresIn())
//				.sameSite("Lax")
//				.build();
//
//		ResponseCookie refreshCookie = ResponseCookie.from("refresh_token", tokens.getRefreshToken())
//				.httpOnly(true)
//				.path("/")
//				.maxAge(60 * 60 * 24 * 30) // 30 days
//				.sameSite("Lax")
//				.build();
//
//		String redirect = "/";
//		if (state != null && !state.isBlank()) {
//			try {
//				byte[] decoded = Base64.getUrlDecoder().decode(state);
//				redirect = new String(decoded, StandardCharsets.UTF_8);
//			} catch (IllegalArgumentException e) {
//				// ignore
//			}
//		}
//
//		HttpHeaders headers = new HttpHeaders();
//		headers.setLocation(URI.create(redirect));
//		headers.add(HttpHeaders.SET_COOKIE, accessCookie.toString());
//		headers.add(HttpHeaders.SET_COOKIE, refreshCookie.toString());
//		return ResponseEntity.status(302).headers(headers).build();
//	}
//
//	@GetMapping("/user")
//	public ResponseEntity<?> user(HttpServletRequest request) {
//		String token = null;
//		if (request.getCookies() != null) {
//			for (Cookie c : request.getCookies()) {
//				if ("access_token".equals(c.getName())) {
//					token = c.getValue();
//					break;
//				}
//			}
//		}
//		if (token == null) {
//			return ResponseEntity.status(401).body(Map.of("error", "not_authenticated"));
//		}
//
//		Map<String, Object> user = authService.userInfo(token);
//		return ResponseEntity.ok(user);
//	}
//
//	@PostMapping("/refresh")
//	public ResponseEntity<?> refresh(HttpServletRequest request) {
//		String refreshToken = null;
//		if (request.getCookies() != null) {
//			for (Cookie c : request.getCookies()) {
//				if ("refresh_token".equals(c.getName())) {
//					refreshToken = c.getValue();
//					break;
//				}
//			}
//		}
//		if (refreshToken == null) {
//			return ResponseEntity.status(401).body(Map.of("error", "no_refresh_token"));
//		}
//
//		TokenResponse tokens = authService.refresh(refreshToken);
//
//		ResponseCookie accessCookie = ResponseCookie.from("access_token", tokens.getAccessToken())
//				.httpOnly(true)
//				.path("/")
//				.maxAge(tokens.getExpiresIn())
//				.sameSite("Lax")
//				.build();
//
//		HttpHeaders headers = new HttpHeaders();
//		headers.add(HttpHeaders.SET_COOKIE, accessCookie.toString());
//		return ResponseEntity.ok().headers(headers).body(Map.of("status", "ok"));
//	}
//
//	@PostMapping("/logout")
//	public ResponseEntity<Void> logout(HttpServletRequest request) {
//		String accessToken = null;
//		String refreshToken = null;
//		if (request.getCookies() != null) {
//			for (Cookie c : request.getCookies()) {
//				if ("access_token".equals(c.getName())) {
//					accessToken = c.getValue();
//				}
//				if ("refresh_token".equals(c.getName())) {
//					refreshToken = c.getValue();
//				}
//			}
//		}
//
//		if (accessToken != null) {
//			authService.revoke(accessToken, "access_token");
//		}
//		if (refreshToken != null) {
//			authService.revoke(refreshToken, "refresh_token");
//		}
//
//		ResponseCookie clearAccess = ResponseCookie.from("access_token", "").httpOnly(true).path("/").maxAge(0).build();
//		ResponseCookie clearRefresh = ResponseCookie.from("refresh_token", "").httpOnly(true).path("/").maxAge(0).build();
//
//		HttpHeaders headers = new HttpHeaders();
//		headers.add(HttpHeaders.SET_COOKIE, clearAccess.toString());
//		headers.add(HttpHeaders.SET_COOKIE, clearRefresh.toString());
//		headers.setLocation(URI.create("/"));
//		return ResponseEntity.status(302).headers(headers).build();
//	}
	
}
