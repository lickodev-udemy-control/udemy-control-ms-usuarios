package mx.com.lickodev.udemy.control.users.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import mx.com.lickodev.udemy.control.commons.filters.AuthorizationCustomFilter;

@Configuration
@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(prePostEnabled = true)
/**
 * https://stackoverflow.com/questions/42632163/how-preauthorize-checks-the-roles
 */
public class GlobalWebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private Environment environment;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();

		http.authorizeRequests().antMatchers("*/**").authenticated().anyRequest().authenticated().and()
				.addFilter(new AuthorizationCustomFilter(authenticationManager(), environment));
		http.headers().frameOptions().disable();
	}

}