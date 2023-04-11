package shop.mtcoding.securityapp.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

import lombok.RequiredArgsConstructor;
import shop.mtcoding.securityapp.core.auth.MyUserDetails;
import shop.mtcoding.securityapp.dto.ResponseDTO;
import shop.mtcoding.securityapp.dto.UserRequest;
import shop.mtcoding.securityapp.dto.UserResponse;
import shop.mtcoding.securityapp.service.UserService;

@RequiredArgsConstructor
@Controller
public class HelloController {

    private final UserService userService;

    @GetMapping("/users/{id}")
    public ResponseEntity<?> userCheck(@PathVariable Long id, @AuthenticationPrincipal MyUserDetails myUserDetails) {
        String username = myUserDetails.getUser().getUsername();
        String role = myUserDetails.getUser().getRole();

        return ResponseEntity.ok().body(username + " : " + role);

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
