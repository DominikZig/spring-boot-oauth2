package com.myprojects.springbootoauth2;

import org.apache.catalina.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.CompositeFilter;

import javax.servlet.Filter;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
@EnableOAuth2Client
@RestController
public class SpringBootOauth2Application extends WebSecurityConfigurerAdapter
{
	@Autowired
	OAuth2ClientContext oAuth2ClientContext;

	@RequestMapping("/user")
	public Principal user(Principal principal)
	{
		//generally not a good idea to return a whole Principal, since it might expose info that the browser client doesn't need to know
		return principal; //describes the currently authenticated user
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception
	{
		http
				.antMatcher("/**")
				.authorizeRequests()
					.antMatchers("/", "/login**", "/webjars/**", "/error**")
					.permitAll()
				.anyRequest()
					.authenticated()
				.and().exceptionHandling().authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/"))
		        .and().logout().logoutSuccessUrl("/").permitAll()
                .and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
				.and().addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);
	}

	private Filter ssoFilter()
	{
        CompositeFilter filter = new CompositeFilter();
        List<Filter> filters = new ArrayList<>();

        OAuth2ClientAuthenticationProcessingFilter facebookFilter = new OAuth2ClientAuthenticationProcessingFilter("/login/facebook");
        OAuth2RestTemplate facebookTemplate = new OAuth2RestTemplate(facebook(), oAuth2ClientContext);

        facebookFilter.setRestTemplate(facebookTemplate);

        UserInfoTokenServices tokenServices = new UserInfoTokenServices(facebookResource().getUserInfoUri(), facebook().getClientId());

        tokenServices.setRestTemplate(facebookTemplate);
        facebookFilter.setTokenServices(tokenServices);
        filters.add(facebookFilter);

        OAuth2ClientAuthenticationProcessingFilter githubFilter = new OAuth2ClientAuthenticationProcessingFilter("/login/github");
        OAuth2RestTemplate githubTemplate = new OAuth2RestTemplate(github(), oAuth2ClientContext);

        githubFilter.setRestTemplate(githubTemplate);

        tokenServices = new UserInfoTokenServices(githubResource().getUserInfoUri(), github().getClientId());
        tokenServices.setRestTemplate(githubTemplate);

        githubFilter.setTokenServices(tokenServices);

        filters.add(githubFilter);

        filter.setFilters(filters);

        return filter;
	}

	@Bean
	@ConfigurationProperties("facebook.client")
	public AuthorizationCodeResourceDetails facebook()
	{
		return new AuthorizationCodeResourceDetails();
	}

	@Bean
	@ConfigurationProperties("facebook.resource")
	public ResourceServerProperties facebookResource()
	{
		return new ResourceServerProperties();
	}

	@Bean
    @ConfigurationProperties("github.client")
    public AuthorizationCodeResourceDetails github()
    {
        return new AuthorizationCodeResourceDetails();
    }

    @Bean
    @ConfigurationProperties("github.resource")
    public ResourceServerProperties githubResource()
    {
        return new ResourceServerProperties();
    }

	@Bean
	public FilterRegistrationBean<OAuth2ClientContextFilter> oAuth2ClientFilterRegistration(OAuth2ClientContextFilter filter)
	{
		FilterRegistrationBean<OAuth2ClientContextFilter> registration = new FilterRegistrationBean<OAuth2ClientContextFilter>();

		registration.setFilter(filter);
		registration.setOrder(-100);

		return registration;
	}

	public static void main(String[] args)
	{
		SpringApplication.run(SpringBootOauth2Application.class, args);
	}
}
