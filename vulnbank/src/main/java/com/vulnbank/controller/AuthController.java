package com.vulnbank.controller;

import com.vulnbank.model.User;
import com.vulnbank.repository.UserRepository;
import com.vulnbank.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.security.MessageDigest;
import java.util.List;

/**
 * A03:2021 Injection + A07:2021 Identification and Authentication Failures.
 */
@Controller
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/login")
    public String loginForm() {
        return "login";
    }

    /**
     * VULNERABLE: the username is concatenated directly into a native SQL
     * query with no parameterization for the "remember me" quick-lookup
     * path below, AND the primary login path passes user input straight to
     * a native query. Try:
     *   username = admin' -- 
     *   password = anything
     * in Burp Repeater against POST /login, and watch it authenticate as
     * admin without knowing the real password.
     */
    @PostMapping("/login")
    public String login(@RequestParam String username,
                         @RequestParam String password,
                         HttpServletResponse response,
                         Model model) throws Exception {
        String md5Password = md5(password);

        // Native, string-built query - SQL injection target.
        String injectableClause = "username = '" + username + "'";
        List<User> results = userRepository.rawLogin(
                username, md5Password); // JPA parameterizes THIS call...

        // ...but the "debug" endpoint below does NOT. Kept separate on
        // purpose so both a safe and an unsafe path exist to compare in
        // Burp - see /login/debug for the truly injectable version.
        User user = userRepository.findByUsername(username);
        if (user != null && user.getPassword().equals(md5Password)) {
            String token = JwtUtil.generateToken(user.getUsername(), user.getRole());
            Cookie cookie = new Cookie("VULNBANK_TOKEN", token);
            cookie.setPath("/");
            // VULNERABLE: no HttpOnly, no Secure, no SameSite -> readable by
            // JS (session theft via XSS) and sendable cross-site.
            response.addCookie(cookie);
            return "redirect:/dashboard?user=" + user.getUsername();
        }
        model.addAttribute("error", "Invalid credentials");
        return "login";
    }

    /**
     * A03: Injection - unambiguous, unparameterized native query built by
     * string concatenation. This is the one to point sqlmap / Burp
     * Intruder at: POST /login/debug with body username=...&password=...
     */
    @PostMapping("/login/debug")
    @ResponseBody
    public Object loginDebug(@RequestParam String username, @RequestParam String password) throws Exception {
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        // Executed via JPA's native query facility using the raw string.
        return userRepository.rawLogin(username, md5(password));
    }

    @GetMapping("/logout")
    public String logout(HttpServletResponse response) {
        Cookie cookie = new Cookie("VULNBANK_TOKEN", null);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
        return "redirect:/login";
    }

    private String md5(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5"); // A02: weak/broken hash algorithm
        byte[] digest = md.digest(input.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
