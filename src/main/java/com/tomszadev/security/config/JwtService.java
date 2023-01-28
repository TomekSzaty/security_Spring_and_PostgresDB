package com.tomszadev.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.function.Function;

@Service
public class JwtService {

    private final static String SECRET_KEY = "50655368566B5970337336763979244226452948404D635166546A576E5A7134";
    public String extractUsername(String jwToken) {
        return extractClaim(jwToken, Claims::getSubject);
    }
    public <T> T extractClaim(String jwToken, Function<Claims, T> claimResolver) {
        final Claims claims = extractAllClaims(jwToken);
        return claimResolver.apply(claims);
    }

    private Claims extractAllClaims(String jwToken) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(jwToken)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
