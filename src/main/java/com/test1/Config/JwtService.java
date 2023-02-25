package com.test1.Config;

import com.test1.User.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.function.Function;

@Service
public class JwtService {
    private final static String SECRET_KEY = "6D5A7134743777397A24432646294A404E635266556A586E3272357538782F41";
    public String extractUserName(String token) {
        return extractClaim(token,Claims::getSubject);
    }
    public <T> T extractClaim(String token, Function<Claims,T> function) {
        final Claims claims = extractAllClaims(token);
        return function.apply(claims);

    }

    public String generateToken(HashMap<String,Object> map, UserDetails userDetails) {
        return Jwts.builder().setClaims(map).setSubject(userDetails.getUsername()).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()*1000*60*24))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256).compact();

    }
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUserName(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));

    }
    public Date getTokenExpiration(String token) {
        return extractClaim(token,Claims::getExpiration);
    }
    public boolean isTokenExpired(String token) {
        return getTokenExpiration(token).before(new Date());
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token).getBody();
    }
    private Key getSigningKey() {
        byte[] key = Decoders.BASE64URL.decode(SECRET_KEY);
        //return Keys.hmacShaKeyFor(key);
        return Keys.hmacShaKeyFor(key);
    }


    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(),userDetails);
    }
}
