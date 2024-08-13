package com.rezguiyassine.springsecurityProject.config;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    private final  static  String SECRET_Key="3F8AD48BDD882413D8FDDCBFB8983";
    // Extract the username from the token
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    //generate token with the user details only
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(),userDetails);
    }



    // generate a token with the claims and the user details
    public String generateToken(Map<String ,Object> extrClaims,
            UserDetails userDetails) {

        return Jwts.builder().setClaims(extrClaims).setSubject(userDetails.getUsername())
                .setIssuedAt(new java.util.Date(System.currentTimeMillis()))
                .setExpiration(new java.util.Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
                .signWith(getSignInKey(),SignatureAlgorithm.HS256)
                .compact();
    }


    // Extract the   claims from the token and returns a specific claim of type T.
    public <T> T extractClaim(String token , Function<Claims ,T>claimsTFunction){
        final Claims claims = extractAllClaims(token);
        return claimsTFunction.apply(claims);
    }


    // Extract the claims from the token and return them as a Claims object
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
    // Get the key from the secret key in the application.properties file and decode it to a byte array and return it as a Key
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_Key);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
