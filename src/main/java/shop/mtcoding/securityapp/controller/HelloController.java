package shop.mtcoding.securityapp.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import shop.mtcoding.securityapp.core.auth.MyUserDetails;
import shop.mtcoding.securityapp.core.jwt.MyJwtProvider;
import shop.mtcoding.securityapp.dto.ResponseDTO;
import shop.mtcoding.securityapp.dto.UserRequest;
import shop.mtcoding.securityapp.dto.UserResponse;
import shop.mtcoding.securityapp.model.UserRepository;
import shop.mtcoding.securityapp.service.UserService;

/**
 * 로그 레벨 : trace, debug, info, warn, error
 */

@Slf4j
@RequiredArgsConstructor
@Controller
public class HelloController {

    private final UserService userService;
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;

    @Value("${meta.name}")
    private String name;

    @GetMapping("/tes")
    public ResponseEntity<?> tes() {
        return ResponseEntity.ok().body(name);
    }

    @PostMapping("/login")
    // @Vaild 붙여서 처리 가능
    public ResponseEntity<?> login(@RequestBody UserRequest.LoginDTO loginDTO) {
        String jwt = userService.로그인(loginDTO);

        // userdetailsService 안쓴 코드
        return ResponseEntity.ok().header(MyJwtProvider.HEADER, jwt).body("로그인완료");
    }

    @GetMapping("/users/1")
    public ResponseEntity<?> userCheck(@AuthenticationPrincipal MyUserDetails myUserDetails) {
        Long id = myUserDetails.getUser().getId();
        String role = myUserDetails.getUser().getRole();

        return ResponseEntity.ok().body(id + " : " + role);
    }

    @GetMapping("/")
    public ResponseEntity<?> hello() {

        return ResponseEntity.ok().body("ok");
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @PostMapping("/join")
    public ResponseEntity<?> join(UserRequest.JoinDTO joinDTO) {
        // select 됨
        UserResponse.JoinDto data = userService.회원가입(joinDTO);
        // select 안됨
        ResponseDTO<?> responseDTO = new ResponseDTO<>().data(data);
        return ResponseEntity.ok().body(responseDTO);
    }
}
