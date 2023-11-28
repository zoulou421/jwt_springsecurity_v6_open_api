package com.formationkilo.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.ConfigurationKeys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.validation.DefaultMessageCodesResolver;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    //link:https://generate-random.org/encryption-key-generator
    private static final String SECRET_KEY="6gzazi4dCXibx/PLvKo6/kxUwxD087vYr/6QlwD6i5LuyaHW7FTKJlZ0CahFDGYJ0JSHWOjCdsVL0WXybNPXW8VnTUZbr9DxpCiq9E/KbVvxUe8/3XfHeOvIqjXXQP2bNcwJV7ZbiBzgSj16NDBpgJJ0wZl94WsdXXeFDCkipvGVwcbItPgoDrWk1dl7grmpZKQoL7s8Hz7rHJ6HCYAzbpyOUUylRuiO1LJlggyyMYYwEJwKAgK7JoGjFkLh2TWd1vCsL8slbaJntmweJkYB1TcGkIWNFbHtqP4Nd5AIBHF0w+vx46XVXVolcgN2Q3q7D2chYdM8L1xlqsMBqIhoM9Yf/YH/+JtyQELMDNtihwU=\n";
   //4
    public String extractUsername(String token) {
       return extractClaim(token, Claims::getSubject);
    }
    //3
    public <T> T extractClaim(String token, Function<Claims,T> claimsResolver){
      final Claims claims=extractAllClaims(token);
      return claimsResolver.apply(claims);
    }
    //1
    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
    //2
    private Key getSignInKey() {
        byte[] keyBytes= Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
    //5
    public String generateToken(Map<String,Object>extractClaims, UserDetails userDetails) {
      return Jwts
              .builder()
              .setClaims(extractClaims)
              .setSubject(userDetails.getUsername())
              .setIssuedAt(new Date(System.currentTimeMillis()))
              .setExpiration(new Date(System.currentTimeMillis()+1000*60*24))
              .signWith(getSignInKey(), SignatureAlgorithm.HS256)
              .compact();
    }
    //6
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(),userDetails);
    }
    //7
    public boolean isTokenValid(String token, UserDetails userDetails){ //we wanna validate if this token belong to that user
       final String username=extractUsername(token);
       return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }
    //8
    private boolean isTokenExpired(String token) {
      return extractExpiration(token).before(new Date());
    }
    //9
    private Date extractExpiration(String token) {
        return extractClaim(token,Claims::getExpiration);
    }


}