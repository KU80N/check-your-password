package pl.checkyourpassword.service;

import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

@Service
public class PasswordCheckServiceImpl implements PasswordCheckService{

    private static final Pattern UPPER_CASE_PATTERN = Pattern.compile("[A-Z]");
    private static final Pattern DIGIT_PATTERN = Pattern.compile("\\d");
    private static final Pattern SPECIAL_CHAR_PATTERN = Pattern.compile("\\W");

    @Override
    public String isPasswordSafe(String password) {
        List<String> feedback = new ArrayList<>();

        if (password.length() < 8) {
            feedback.add("Password must be at least 8 characters long.");
        }
        if (!UPPER_CASE_PATTERN.matcher(password).find()) {
            feedback.add("Password must contain at least one uppercase letter.");
        }
        if (!DIGIT_PATTERN.matcher(password).find()) {
            feedback.add("Password must contain at least one digit.");
        }
        if (!SPECIAL_CHAR_PATTERN.matcher(password).find()) {
            feedback.add("Password must contain at least one special character.");
        }

        return feedback.isEmpty() ? "Password is strong" : String.join(" ", feedback);
    }
}
