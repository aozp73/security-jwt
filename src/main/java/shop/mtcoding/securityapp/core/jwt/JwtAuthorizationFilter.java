package shop.mtcoding.securityapp.core.jwt;

import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;

import lombok.extern.slf4j.Slf4j;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import shop.mtcoding.securityapp.core.auth.MyUserDetails;
import shop.mtcoding.securityapp.model.User;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// BasicAuthenticationFilter는 모든 주소에서 발동하는 코드임
@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        // 토큰이 있다면 저장하고, 없다면 통과

        String prefixJwt = request.getHeader(MyJwtProvider.HEADER);
        // 토큰 있는지 확인
        if (prefixJwt != null) {
            // 있으면 session에 넣고
            String jwt = prefixJwt.replace(MyJwtProvider.TOKEN_PREFIX, "");
            try {
                DecodedJWT decodedJWT = MyJwtProvider.verify(jwt);
                Long id = decodedJWT.getClaim("id").asLong();
                String role = decodedJWT.getClaim("role").asString();

                User user = User.builder().id(id).role(role).build();
                MyUserDetails myUserDetails = new MyUserDetails(user);
                Authentication authentication = new UsernamePasswordAuthenticationToken(
                        myUserDetails,
                        myUserDetails.getPassword(),
                        myUserDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (SignatureVerificationException sve) {
                // 없다면 다음 필터로 가게 -> 주소에 대한 권한 처리를 Security가 이후에 처리할 것이기 때문에 괜찮음
                // chain.doFilter(request, response);
                // return;
                log.error("토큰 검증 실패");
                chain.doFilter(request, response);
            } catch (TokenExpiredException tee) {
                // chain.doFilter(request, response);
                // return;
                log.error("토큰 만료");
                chain.doFilter(request, response);
            }
        }
        chain.doFilter(request, response);
    }
}