package com.example.demo.filter;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.web.WebProperties.Resources.Chain;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.preauth.j2ee.J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.demo.util.JwtUtil;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JWTRequestFilter extends OncePerRequestFilter {

	@Autowired
	private JwtUtil jwtUtil;
	@Autowired
	private UserDetailsService userdetailsService;
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
 		
		// Get Authorization Header from request
		String authHeader=request.getHeader("Authorization");
		
		//extract username from the token
		String username=null;
		String jwt=null;
		
		if(authHeader!=null&&authHeader.startsWith("Bearer ")) {
			//Authorization= Bearer <token>
		jwt=authHeader.substring(7);
		username=jwtUtil.extractUsername(jwt);
			}
		
		//load userdat based on user using UserDetailsService
	
		if(username!=null && SecurityContextHolder.getContext().getAuthentication()==null) {
		UserDetails userDetails=	userdetailsService.loadUserByUsername(username);
		//validate token with userdetails
		if(jwtUtil.validateToken(jwt, userDetails)) {
			UsernamePasswordAuthenticationToken unmaepwd=new UsernamePasswordAuthenticationToken(userDetails,null, userDetails.getAuthorities());
			unmaepwd.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
			SecurityContextHolder.getContext().setAuthentication(unmaepwd);
		}
		}
		filterChain.doFilter(request, response);
	}

}
