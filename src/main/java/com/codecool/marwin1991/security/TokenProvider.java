package com.codecool.marwin1991.security;

import com.codecool.marwin1991.config.AppConfig;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.Date;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenProvider {

    private final AppConfig appConfig;

    public String createToken(Authentication authentication) {

      UserPrincipal userPrincipal=(UserPrincipal) authentication.getPrincipal();
      Date now =new Date();
        Date exiration =new Date(now.getTime()+appConfig.getTokenExpirationMsec());

        return Jwts.builder()
                .setSubject(userPrincipal.getId())
                .setIssuedAt(now)
                .setExpiration(exiration)
                .signWith(SignatureAlgorithm.ES512, appConfig.getTokenSecret())
                .compact();
    }

    public String getUserIdFromToken(String token) {



       Claims claims=Jwts.parser()
               .setSigningKey(appConfig.getTokenSecret())
               .parseClaimsJws(token)
               .getBody();
       return claims.getSubject();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .setSigningKey(appConfig.getTokenSecret())
                    .parseClaimsJws(token);
            return true;
        } catch (SignatureException e){
            log.info("Signature JWT is invalid");
        } catch (ExpiredJwtException e){
            log.info("JWT is exoired");
        } catch (Exception e){
            log.error("JWT problem !!!!, a");
        }
        return false;


    }
}
