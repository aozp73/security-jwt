package shop.mtcoding.securityapp.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import lombok.extern.slf4j.Slf4j;
import shop.mtcoding.securityapp.core.jwt.JwtAuthorizationFilter;

@Slf4j
@Configuration
public class SecurityConfig {
    @Bean
    BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // JWT 필터 등록이 필요함
    public class CustomSecurityFilterManager extends AbstractHttpConfigurer<CustomSecurityFilterManager, HttpSecurity> {
        @Override
        public void configure(HttpSecurity builder) throws Exception {
            AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);

            // 1) 바꿔치기 2) disabled하고 아무 곳이나 등록 아래코드는 1)바꿔치기
            builder.addFilterAt(new JwtAuthorizationFilter(authenticationManager), BasicAuthenticationFilter.class);
            super.configure(builder);
        }
    }

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // 1. CSRF 해제
        http.csrf().disable(); // postman 접근해야 함!! - CSR 할때!!

        // 2. ifram 거부
        http.headers().frameOptions().disable();

        // 3. cors 재설정
        http.cors().configurationSource(configurationSource());

        // 4. jSessionId 사용 거부
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        // 5. form 로그인 해제
        http.formLogin().disable();

        // // 6. httpBasic 정책 해제 (BasicAuthenticationFilter 해제하는 것)
        // http.httpBasic().disable();

        // 6. XSS (lucy 필터)

        // 7. 커스텀 필터 적용 (시큐리티 필터 교환)
        http.apply(new CustomSecurityFilterManager());

        // 8. 인증 실패 처리 (Filter에서 처리는 throw로 못하고 이렇게 할 수 있음)
        http.exceptionHandling().authenticationEntryPoint((request, response, authException) -> {
            log.debug("디버그 : 인증 실패 : " + authException.getMessage());
            log.info("인포 : 인증 실패 : " + authException.getMessage());
            log.warn("워닝 : 인증 실패 : " + authException.getMessage());
            log.error("에러 : 인증 실패 : " + authException.getMessage());

            response.setContentType("text/plain; charset=utf-8");
            response.setStatus(401);
            response.getWriter().print("인증 실패");
            // checkpoint - 나중에 작성 (예외핸들러 처리를 하지 못함, DS전에 있는 Filter이기 떄문에 따로 만들어야함)
        });

        // 9. 권한 실패 처리
        http.exceptionHandling().accessDeniedHandler((request, response, accessDeniedException) -> {
            log.debug("디버그 : 권한 실패 : " + accessDeniedException.getMessage());
            log.info("인포 : 권한 실패 : " + accessDeniedException.getMessage());
            log.warn("워닝 : 권한 실패 : " + accessDeniedException.getMessage());
            log.error("에러 : 권한 실패 : " + accessDeniedException.getMessage());
            response.setContentType("text/plain; charset=utf-8");
            response.setStatus(403);
            response.getWriter().print("권한 실패");
        });

        // // 2. Form 로그인 설정
        // http.formLogin()
        // .loginPage("/loginForm")
        // .usernameParameter("username")
        // .passwordParameter("password")
        // .loginProcessingUrl("/login") // POST + X-WWW-Form-urlEncoded
        // // .defaultSuccessUrl("/")
        // .successHandler((eq, resp, authentication) -> {
        // System.out.println("디버그 : 로그인이 완료되었습니다");
        // resp.sendRedirect("/");
        // })
        // .failureHandler((req, resp, ex) -> {
        // System.out.println("디버그 : 로그인 실패 -> " + ex.getMessage());
        // });

        // 10. 인증, 권한 필터 설정
        http.authorizeRequests(
                authroize -> authroize.antMatchers("/users/**").authenticated()
                        .antMatchers("/manager/**")
                        .access("hasRole('ADMIN') or hasRole('MANAGER')")
                        .antMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().permitAll());

        return http.build();
    }

    public CorsConfigurationSource configurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedHeader("*");
        configuration.addAllowedMethod("*"); // GET, POST, PUT, DELETE (Javascript 요청 허용)
        configuration.addAllowedOriginPattern("*"); // 모든 IP 주소 허용 (프론트 앤드 IP만 허용 react)
        configuration.setAllowCredentials(true); // 클라이언트에서 쿠키 요청 허용
        configuration.addExposedHeader("Authorization"); // 옛날에는 디폴트 였다. 지금은 아닙니다.
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
