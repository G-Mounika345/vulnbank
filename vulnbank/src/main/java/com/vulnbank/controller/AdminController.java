package com.vulnbank.controller;

import com.vulnbank.model.User;
import com.vulnbank.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * A01:2021 Broken Access Control + A09:2021 Security Logging and
 * Monitoring Failures.
 *
 * "Access control" here is just checking a request parameter against a
 * hardcoded password pulled from config - there is no real session/role
 * check, so it can be bypassed trivially once you find (or brute force
 * with Burp Intruder) the parameter name and value. There is also zero
 * logging of admin actions or failed access attempts, so none of this
 * would show up in an audit trail (A09).
 */
@RestController
@RequestMapping("/admin")
public class AdminController {

    @Autowired
    private UserRepository userRepository;

    @Value("${app.admin.backdoor.password}")
    private String backdoorPassword;

    /**
     * VULNERABLE "access control": GET /admin/users?key=Sup3rAdmin!2023
     * dumps every user INCLUDING their MD5 password hashes. The check is
     * easily bypassed once the key leaks (e.g. via the exposed actuator
     * /actuator/env endpoint - chain A05 -> A01) or is brute-forced.
     */
    @GetMapping("/users")
    public List<User> listUsers(@RequestParam(required = false) String key) {
        if (key == null || !key.equals(backdoorPassword)) {
            return List.of(); // "denied" - but note: no 401/403, no logging, no lockout
        }
        return userRepository.findAll();
    }

    /**
     * Even more broken: this one has NO check at all. It's reachable by
     * anyone who guesses/finds the URL - a pure "security by obscurity"
     * hidden admin panel, the canonical A01 example.
     */
    @GetMapping("/debug/all-data")
    public Object dumpEverything() {
        return userRepository.findAll();
    }

    /**
     * VULNERABLE: same broken backdoor-key "access control" as
     * listUsers() above, trivially bypassed the same way (leak the key via
     * /actuator/env, or brute-force it with Burp Intruder - no lockout, no
     * rate limiting). On top of that: no confirmation step, no audit
     * logging of who deleted what, and no check that the target `id` isn't
     * the caller's own account or the last remaining admin.
     *
     * Try in Burp: DELETE /admin/users/2?key=Sup3rAdmin!2023 to delete bob
     * as an unauthenticated/low-privileged caller.
     */
    @DeleteMapping("/users/{id}")
    public String deleteUser(@PathVariable Long id, @RequestParam(required = false) String key) {
        if (key == null || !key.equals(backdoorPassword)) {
            return "Access denied"; // "denied" - but again: no 401/403, no logging, no lockout
        }
        userRepository.deleteById(id);
        return "Deleted user " + id;
    }
}
