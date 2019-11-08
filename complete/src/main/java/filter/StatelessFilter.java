package filter;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import javax.management.RuntimeErrorException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import model.LoginState;


/**
 * 接收json
 * @author startsi
 *
 */
public class StatelessFilter extends OncePerRequestFilter {
	
//	private static final String FILTER_APPLIED = "__spring_security_statelessFilter_filterApplied";

	@Override
	protected void doFilterInternal(HttpServletRequest servletRequest, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		System.out.println("getContentType : " + servletRequest.getContentType() + "   url:" + servletRequest.getRequestURL());
	  	String token = servletRequest.getHeader("X-Token");
	  	if(!StringUtils.isEmpty(token)) {
	  		// 假设是从缓存中获取的
	  		List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
	  		GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_EMPLOYEE");
	          grantedAuthorities.add(grantedAuthority);
	  		LoginState userDetails = new LoginState("张三", "123", grantedAuthorities);
	  		
	  		SecurityContextHolder.getContext().setAuthentication(
	                  new UsernamePasswordAuthenticationToken(userDetails, null,
	                      userDetails.getAuthorities()));
	  	} else {
	//  		throw new RuntimeException("1");
	  	}
	  	
//	  	servletRequest.setAttribute(FILTER_APPLIED,true);
	  	filterChain.doFilter(servletRequest, response);
	}

//	public void doFilter(ServletRequest req, ServletResponse res, FilterChain filterChain)
//			throws IOException, ServletException {
//		HttpServletRequest servletRequest = (HttpServletRequest) req;
//		
//		if (servletRequest.getAttribute(FILTER_APPLIED) != null) {
//            filterChain.doFilter(req, res);
//            return ;
//        }
//		
//		System.out.println("getContentType : " + servletRequest.getContentType() + "   url:" + servletRequest.getRequestURL());
//    	String token = servletRequest.getHeader("X-Token");
//    	if(!StringUtils.isEmpty(token)) {
//    		// 假设是从缓存中获取的
//    		List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
//    		GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_EMPLOYEE");
//            grantedAuthorities.add(grantedAuthority);
//    		LoginState userDetails = new LoginState("张三", "123", grantedAuthorities);
//    		
//    		SecurityContextHolder.getContext().setAuthentication(
//                    new UsernamePasswordAuthenticationToken(userDetails, null,
//                        userDetails.getAuthorities()));
//    	} else {
////    		throw new RuntimeException("1");
//    	}
//    	
//    	servletRequest.setAttribute(FILTER_APPLIED,true);
//    	filterChain.doFilter(req, res);
//		
//	}
}