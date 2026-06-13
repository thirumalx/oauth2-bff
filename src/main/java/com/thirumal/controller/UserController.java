package com.thirumal.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class UserController {

    @GetMapping("/userinfo")
    public Map<String, Object> getUserInfo(@AuthenticationPrincipal OidcUser user) {
        if (user != null) {
            return Map.of(
                "authenticated", true,
                "name", user.getFullName() != null ? user.getFullName() : user.getName(),
                "email", user.getEmail() != null ? user.getEmail() : "",
                "claims", user.getClaims()
            );
        }
        return Map.of("authenticated", false);
    }
}
