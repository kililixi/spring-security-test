package hello;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
public class AdminController {


    @GetMapping("/greeting")
    public String greeting() {
    	Authentication user = SecurityContextHolder.getContext().getAuthentication();
    	User usera = (User) user.getPrincipal();
    	System.out.println(user.toString());
    	// SecurityContextHolder.getContext().setAuthentication(authResult);
        return "Hello,World!";
    }

    @GetMapping("/login")
    public String login() {

        return "login sucess";
    }
}
