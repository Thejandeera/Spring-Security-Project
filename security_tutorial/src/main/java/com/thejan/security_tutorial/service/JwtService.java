package com.thejan.security_tutorial.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import io.jsonwebtoken.Jwts;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "bccddd8ee98d55f4541ab9b01b23d8110eae13c6feed0f6c1b428470d94f1cdad20f6b38885cbd5f5d457d5e39146b85f19930b2cbd61c5bddb5eacd01e29d20bf10b2e335135afc2f8de652bb67803040288241e51eb00e11cf54392463329386eb099968103f37561086c15b96f2e33259c2089339fc41430e4bbc4b94dfc2aadea375ee1882f5d8a2b416d3bcdec774b274ab7a16dd57428577e79a550397d8f229fca91a9c54e125ebd57e8c46068fa61243d6f8f411d01afc86846202e76164004052e6c6882c66d619d029ad261ca82afa14466b04285fa412e2bd0498d4ded849a7b3fb0897b0b7eef5df6cdf690f2c7dd52974dccc6c49824c174870";

    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims , T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    // generate jwt token using algorithm and secret key
    public String generateToken (Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid (String token, UserDetails userDetails) {
        final String username = extractUserName(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token) ;
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }


    private Claims extractAllClaims(String token){
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
