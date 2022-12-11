package com.doremi.ddd.config.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.savedrequest.NullRequestCache;

import javax.sql.DataSource;

@EnableWebSecurity
@Configuration
public class WebSecurityConfig {
    public static final String AUTHCOOKIENAME = "AUTH";

    @Autowired
    private DataSource dataSource;

    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.securityContext().securityContextRepository(new CookieSecurityContextRepository(users(dataSource)));
        http.requestCache().requestCache(new NullRequestCache());

        http
                .authorizeHttpRequests((authz) -> authz
                        .requestMatchers("/", "/home", "/categories/**", "/products/**").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
//                .authorizeRequests()
//                .antMatchers("/", "/home", "/categories/**", "/products/**").permitAll()
//                .antMatchers("/admin/**").hasRole("ADMIN")
//                .anyRequest().authenticated()
//                .and()
                .formLogin() // login
//                .loginPage("/login")
                .permitAll()
                .successHandler(new CustomAuthSuccessHandler())
                .and()
                .logout() // /login?logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/loggedOut")
                .deleteCookies(AUTHCOOKIENAME)
                .permitAll()
                .and()
                .csrf().disable()
        ;
        return http.build();
    }

    @Bean
    public UserDetailsManager users(DataSource dataSource) {
        JdbcUserDetailsManager users = new JdbcUserDetailsManager(dataSource);
        users.setUsersByUsernameQuery("select member_id, password, 'true' from member where member_id = ?");
        users.setAuthoritiesByUsernameQuery("select member_id, authority from member_authorities where member_id = ?");
        return users;
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers("/vendor/**", "/api/**", "/images/**", "/favicon.ico");
    }
}
