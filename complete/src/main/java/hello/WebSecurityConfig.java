package hello;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import filter.CustomAuthenticationFilter;
import filter.StatelessFilter;
import handler.FailureAuthenticationHandler;
import handler.SuccessAuthenticationHandler;
import provider.AccountVerificationAuthenticationProvider;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
    private UserDetailsService userDetailsService;
	
	@Autowired
	private AccountVerificationAuthenticationProvider accountVerificationAuthenticationProvider;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    @Override
    public void configure(WebSecurity web) throws Exception {
    	web
        	.ignoring()
            .antMatchers("/public/**");
    }

    
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        	auth.authenticationProvider(accountVerificationAuthenticationProvider)
        		.userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder());//passwoldEncoder是对密码的加密处理，如果user中密码没有加密，则可以不加此方法。注意加密请使用security自带的加密方式。
    }
    
    protected void configure1(HttpSecurity http) throws Exception {
    	http.csrf().disable()//禁用了 csrf 功能
    		.sessionManagement().sessionCreationPolicy(
                SessionCreationPolicy.STATELESS)
    		.and()
        	.authorizeRequests()//限定签名成功的请求
        	.antMatchers("/decision/**","/govern/**","/employee/*").hasAnyRole("EMPLOYEE","ADMIN")//对decision和govern 下的接口 需要 USER 或者 ADMIN 权限
        	.antMatchers("/employee/login").permitAll()///employee/login 不限定
        	.antMatchers("/admin/**").hasRole("ADMIN")//对admin下的接口 需要ADMIN权限
        	.antMatchers("/oauth/**").permitAll()//不拦截 oauth 开放的资源
        	.anyRequest().permitAll()//其他没有限定的请求，允许访问
        	.and().anonymous()//对于没有配置权限的其他请求允许匿名访问
        		.and()
        	.formLogin()
        		.loginProcessingUrl("/api/v1/login")
//        		.successHandler(new SuccessAuthenticationHandler())
//        		.failureHandler(new FailureAuthenticationHandler())
        	;//使用 spring security 默认登录页面
//        	.and().httpBasic();//启用http 基础验证
    	// 如果重写了 UsernamePasswordAuthenticationFilter , 覆盖该过滤器
    	http.addFilterAt(customAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    	http.addFilterBefore(customStatelessFilter(), UsernamePasswordAuthenticationFilter.class);
    }
    
    protected void configure(HttpSecurity http) throws Exception {
    	http
    		.csrf().disable()//禁用了 csrf 功能
    		.sessionManagement().sessionCreationPolicy(
                SessionCreationPolicy.STATELESS)
    	.and()
        	.authorizeRequests()//限定签名成功的请求
        	.accessDecisionManager(accessDecisionManager())
        	.antMatchers("/admin/login").permitAll()///employee/login 不限定
        	.anyRequest().authenticated()
//        	.and().anonymous()//对于没有配置权限的其他请求允许匿名访问
        .and()
        	.formLogin()
        	.loginProcessingUrl("/api/v1/login")
        ;
    	// 如果重写了 UsernamePasswordAuthenticationFilter , 覆盖该过滤器
    	http.addFilterAt(customAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    	http.addFilterBefore(customStatelessFilter(), UsernamePasswordAuthenticationFilter.class);
    }
    
//    protected void configure(HttpSecurity http) throws Exception {
//    	http
//    	.authorizeRequests()
//    	.antMatchers("/", "/home").permitAll()
//    	.anyRequest().authenticated()
//    	.and()
//    	.formLogin()
//    	.loginPage("/login")
//    	.permitAll()
//    	.and()
//    	.logout()
//    	.permitAll();
//    }
    
    
    @Bean
    CustomAuthenticationFilter customAuthenticationFilter() throws Exception {
        CustomAuthenticationFilter filter = new CustomAuthenticationFilter();
        filter.setAuthenticationSuccessHandler(new SuccessAuthenticationHandler());
        filter.setAuthenticationFailureHandler(new FailureAuthenticationHandler());
        filter.setFilterProcessesUrl("/api/v1/login"); //生效的路径，即登陆URL
        
        //这句很关键，重用WebSecurityConfigurerAdapter配置的AuthenticationManager，不然要自己组装AuthenticationManager
        filter.setAuthenticationManager(authenticationManagerBean());
        return filter;
    }
    
    @Bean
    StatelessFilter customStatelessFilter() throws Exception {
        StatelessFilter filter = new StatelessFilter();
        return filter;
    }
    
    @Bean
    public AccessDecisionManager accessDecisionManager() {
        List<AccessDecisionVoter<? extends Object>> decisionVoters
            = Arrays.asList(
            new WebExpressionVoter(),
            // new RoleVoter(),
            new RoleBasedVoter(),
            new AuthenticatedVoter());
        return new UnanimousBased(decisionVoters);
    }

}