package akin.city_card.user.controller;

import akin.city_card.response.ResponseMessage;
import akin.city_card.user.core.request.CreateUserRequest;
import akin.city_card.user.service.abstracts.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/api/user")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @PostMapping("/sign-up")
    public ResponseMessage signUp(@RequestBody CreateUserRequest createUserRequest) {
        return userService.create(createUserRequest);
    }
}
