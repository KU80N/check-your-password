package pl.checkyourpassword.service;

import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class PasswordCheckServiceImpl implements PasswordCheckService{

    private static final Pattern UPPER_CASE_PATTERN = Pattern.compile("[A-Z]");
    private static final Pattern DIGIT_PATTERN = Pattern.compile("\\d");
    private static final Pattern SPECIAL_CHAR_PATTERN = Pattern.compile("\\W");
    private static final String HIBP_API_URL = "https://api.pwnedpasswords.com/range/";

    @Override
    public String isPasswordSafe(String password) {
        List<String> feedback = new ArrayList<>();

        String sha1Hash = sha1Hash(password).toUpperCase();
        String prefix = sha1Hash.substring(0, 5);
        String suffix = sha1Hash.substring(5);

        String response = WebClient.create()
                .get()
                .uri(HIBP_API_URL + prefix)
                .retrieve()
                .bodyToMono(String.class)
                .block();

        if (response != null && response.contains(suffix)) {

            int occurrences = sumOccurrences(response);
            if (occurrences > 0) {
                return "Warning: This password has appeared in " + occurrences + " data breach(es).";
            }
        }

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

    private String sha1Hash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));

            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error generating SHA-1 hash", e);
        }
    }

    public static int sumOccurrences(String input) {
        int totalSum = 0;

        Pattern pattern = Pattern.compile(":(\\d+)");
        Matcher matcher = pattern.matcher(input);

        while (matcher.find()) {
            totalSum += Integer.parseInt(matcher.group(1));
        }

        return totalSum;
    }
}
