package provider;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import model.LoginState;

@Component
public class AccountVerificationAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserDetailsService appAuthenticatedUserService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

    	List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
    	GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_EMPLOYEE");
        grantedAuthorities.add(grantedAuthority);
    	UserDetails appAuthenticatedUser = new LoginState("1", "2", grantedAuthorities);

        PreAuthenticatedAuthenticationToken authenticationToken = new PreAuthenticatedAuthenticationToken(appAuthenticatedUser, "", appAuthenticatedUser.getAuthorities());
        authenticationToken.setAuthenticated(true);

        return authenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }

}
