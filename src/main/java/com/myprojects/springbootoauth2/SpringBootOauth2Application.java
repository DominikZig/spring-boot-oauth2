package com.myprojects.springbootoauth2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@SpringBootApplication
@EnableOAuth2Sso
@RestController
public class SpringBootOauth2Application extends WebSecurityConfigurerAdapter
{

	@RequestMapping("/user")
	public Principal user(Principal principal)
	{
		//generally not a good idea to return a whole Principal, since it might expose info that the browser client doesn't need to know
		return principal; //describes the currently authenticated user
	}

	@Override
	public void configure(HttpSecurity http) throws Exception
	{
		http
				.antMatcher("/**")
				.authorizeRequests()
					.antMatchers("/", "/login**", "webjars/**", "/error**")
					.permitAll()
				.anyRequest()
					.authenticated()
		        .and().logout().logoutSuccessUrl("/").permitAll()
                .and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
	}

	public static void main(String[] args)
	{
		SpringApplication.run(SpringBootOauth2Application.class, args);
	}
}
