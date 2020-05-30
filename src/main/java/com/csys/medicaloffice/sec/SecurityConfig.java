package com.csys.medicaloffice.sec;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.authorizeRequests().antMatchers("/Appointment/**").hasAuthority("ADMIN");
        http.authorizeRequests().antMatchers("/Confer/**").hasAuthority("ADMIN");
        http.authorizeRequests().antMatchers("/Consultation/**").hasAuthority("ADMIN");
        http.authorizeRequests().antMatchers("/HospitalisationLettre/**").hasAuthority("ADMIN");
        http.authorizeRequests().antMatchers("/LettreToConfer/**").hasAuthority("ADMIN");
        http.authorizeRequests().antMatchers("/LigneOrdinnance/**").hasAuthority("ADMIN");
        http.authorizeRequests().antMatchers("/MedicalCertificate/**").hasAuthority("ADMIN");
        http.authorizeRequests().antMatchers("/Medicament/**").hasAuthority("ADMIN");
        http.authorizeRequests().antMatchers("/Ordonnance/**").hasAuthority("ADMIN");
        http.authorizeRequests().antMatchers("/Patient/**").hasAuthority("ADMIN");
        http.authorizeRequests().antMatchers("/Person/**").hasAuthority("ADMIN");
        http.authorizeRequests().antMatchers("/PolyclinicHospital/**").hasAuthority("ADMIN");


        http.authorizeRequests().antMatchers("/Appointment/**").hasAuthority("USER");
        http.authorizeRequests().antMatchers("/Confer/**").hasAuthority("USER");
        http.authorizeRequests().antMatchers("/Medicament/**").hasAuthority("USER");
        http.authorizeRequests().antMatchers("/Patient/**").hasAuthority("USER");
        http.authorizeRequests().antMatchers("/Person/**").hasAuthority("USER");
        http.authorizeRequests().antMatchers("/PolyclinicHospital/**").hasAuthority("USER");


        http.authorizeRequests().anyRequest().authenticated();
        http.addFilterBefore(new JWTAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

}
