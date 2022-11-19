package com.codecool.marwin1991.security;

import com.codecool.marwin1991.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private TokenProvider tokenProvider;

    @Autowired
    private UserService userService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        try{
            String jwt=getJwtFromReqest(request);
            if(StringUtils.hasText(jwt)&&tokenProvider.validateToken(jwt)){
                String userId=tokenProvider.getUserIdFromToken(jwt);
                UserDetails userDetails=userService.loadUserById(userId);

UsernamePasswordAuthenticationToken authenticationToken=
        new UsernamePasswordAuthenticationToken(userDetails,null, userDetails.getAuthorities());

authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        } catch (Exception e){log.error("Cloud not authenticate user " + e);
            }

        filterChain.doFilter(request, response);
    }

    private String getJwtFromReqest(HttpServletRequest request) {
        String token = request.getHeader("Authorization");
        if(token.startsWith("Bearer ")){
            return token.substring(7);
        }
        return "";
    }
}
