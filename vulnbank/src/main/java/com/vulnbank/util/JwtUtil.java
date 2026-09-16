package com.vulnbank.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;

import java.util.Date;

/**
 * A02:2021 Cryptographic Failures + A07:2021 Identification and
 * Authentication Failures.
 *
 * Problems on purpose, for you to find:
 *  1. Hardcoded, short, guessable signing secret (also checked into
 *     application.properties in plaintext).
 *  2. No token expiry enforced anywhere that matters.
 *  3. The parser below trusts whatever algorithm header the token itself
 *     declares in some code paths (see AuthController's "trustedParse"
 *     comment) - a classic "alg:none" / algorithm confusion bug class.
 *
 * Try editing a captured JWT in Burp's JWT/"Inspector" extension (or
 * jwt.io), flipping the role claim to ADMIN, and re-signing with the
 * secret above once you've found it in the source / config.
 */
public class JwtUtil {

    private static final String SECRET = "vulnbank-super-secret-key-123"; // matches application.properties

    public static String generateToken(String username, String role) {
        return Jwts.builder()
                .setSubject(username)
                .claim("role", role)
                .setIssuedAt(new Date())
                // NOTE: no setExpiration() call - tokens never expire.
                .signWith(SignatureAlgorithm.HS256, SECRET)
                .compact();
    }

    public static Claims parseToken(String token) {
        Jws<Claims> jws = Jwts.parser()
                .setSigningKey(SECRET)
                .parseClaimsJws(token);
        return jws.getBody();
    }
}
