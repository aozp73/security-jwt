package shop.mtcoding.securityapp.service;

import java.util.Optional;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import lombok.RequiredArgsConstructor;
import shop.mtcoding.securityapp.core.jwt.MyJwtProvider;
import shop.mtcoding.securityapp.dto.UserRequest;
import shop.mtcoding.securityapp.dto.UserResponse;
import shop.mtcoding.securityapp.model.User;
import shop.mtcoding.securityapp.model.UserRepository;

@RequiredArgsConstructor
@Service
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    /**
     * 1. 트랜잭션 관리
     * 2. 영속성 객체 변경감지
     * 3. RequestDTO 요청받기
     * 4. 비지니스 로직 처리하기
     * 5. ResponseDTO 응답하기
     */
    @Transactional
    public UserResponse.JoinDto 회원가입(UserRequest.JoinDTO joinDTO) {
        // select
        String rawPassword = joinDTO.getPassword();
        String encPassword = passwordEncoder.encode(rawPassword); // 60Byte
        joinDTO.setPassword(encPassword);
        User userPS = userRepository.save(joinDTO.toEntity());
        return new UserResponse.JoinDto(userPS);
    }

    public String 로그인(UserRequest.LoginDTO loginDTO) {
        Optional<User> userOP = userRepository.findByUsername(loginDTO.getUsername());
        // 로그인 유저 아이디가 있다면
        if (userOP.isPresent()) {
            // 있으면 비밀번호 match (details를 안쓸거면 내가 비교해야되고, 암호화 된걸 처리해야 함)
            User userPS = userOP.get();
            // 로그인 입력 값과 DB password를 비교
            if (passwordEncoder.matches(loginDTO.getPassword(), userPS.getPassword())) {
                String jwt = MyJwtProvider.create(userPS); // 토큰 생성1
                return jwt;
            }
            throw new RuntimeException("패스워드 틀렸어");
        } else {
            throw new RuntimeException("유저네임 없어");
        }
    }
}
