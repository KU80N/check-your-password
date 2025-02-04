package pl.checkyourpassword.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pl.checkyourpassword.service.PasswordCheckService;

@RestController
@RequestMapping("/api/password")
public class PasswordCheckController {

    private final PasswordCheckService passwordCheckService;

    @Autowired
    public PasswordCheckController(PasswordCheckService passwordCheckService) {
        this.passwordCheckService = passwordCheckService;
    }

    @PostMapping("check")
    public String checkPassword(@RequestBody String password) {
        return passwordCheckService.isPasswordSafe(password);
    }

}
