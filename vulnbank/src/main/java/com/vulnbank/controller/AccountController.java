package com.vulnbank.controller;

import com.vulnbank.model.Account;
import com.vulnbank.model.User;
import com.vulnbank.repository.AccountRepository;
import com.vulnbank.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

/**
 * A01:2021 Broken Access Control (IDOR - Insecure Direct Object Reference).
 */
@Controller
public class AccountController {

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private UserRepository userRepository;

    /**
     * VULNERABLE: no check that the logged-in user (from the cookie) owns
     * account `id`. Log in as alice, then in Burp just change the id in
     *   GET /account/1  ->  GET /account/3
     * to view admin's balance, or /account/2 for bob's.
     */
    @GetMapping("/account/{id}")
    @ResponseBody
    public Object viewAccount(@PathVariable Long id) {
        Optional<Account> account = accountRepository.findById(id);
        if (account.isPresent()) return account.get();
        return "Not found";
    }

    /**
     * VULNERABLE: identity for the whole dashboard (including which role
     * sees the admin "manage users" panel) is taken straight from the
     * `?user=` query parameter, not from the session/cookie - trivially
     * spoofable. Try /dashboard?user=admin to see the admin panel without
     * ever logging in as admin.
     *
     * Role hierarchy (UI-only - see note on manageableUserIds below):
     *   USER        - alice, bob            - no admin panel
     *   ADMIN       - admin                 - can manage regular account
     *                                         holders (users 1-2) only
     *   CHIEF_ADMIN - chiefadmin            - can manage everyone,
     *                                         including other admins
     */
    @GetMapping("/dashboard")
    public String dashboard(@RequestParam(required = false) String user, Model model) {
        model.addAttribute("username", user);
        User account = user != null ? userRepository.findByUsername(user) : null;
        String role = account != null ? account.getRole() : null;
        model.addAttribute("role", role);

        /*
         * VULNERABLE: this list only controls which edit links the
         * dashboard renders - it is a client-side-only boundary. The
         * backend endpoint it links to, /admin/users/{id}/edit, performs
         * NO role check at all, so a plain "admin" can still edit the
         * chief admin's (or any) record just by typing the URL directly -
         * a classic "security control enforced only in the UI" A01 example.
         */
        if ("CHIEF_ADMIN".equals(role)) {
            model.addAttribute("manageableUserIds", List.of(1L, 2L, 3L, 4L));
        } else if ("ADMIN".equals(role)) {
            model.addAttribute("manageableUserIds", List.of(1L, 2L));
        }

        if (account != null) {
            List<Account> owned = accountRepository.findByOwnerId(account.getId());
            if (!owned.isEmpty()) {
                model.addAttribute("accountId", owned.get(0).getId());
                model.addAttribute("balance", owned.get(0).getBalance());
            }
        }
        return "dashboard";
    }

    /**
     * Another IDOR: balance can be set directly by ID with no ownership
     * or authorization check at all - a mass-assignment-flavored broken
     * access control bug. Try PUT/POST to /account/1/balance?amount=999999.
     */
    @PostMapping("/account/{id}/balance")
    @ResponseBody
    public Object setBalance(@PathVariable Long id, @RequestParam java.math.BigDecimal amount) {
        Optional<Account> accountOpt = accountRepository.findById(id);
        if (accountOpt.isEmpty()) return "Not found";
        Account account = accountOpt.get();
        account.setBalance(amount);
        accountRepository.save(account);
        return account;
    }

    @GetMapping("/accounts")
    @ResponseBody
    public List<Account> allAccounts() {
        // VULNERABLE: dumps every customer's account & balance, no auth check.
        return accountRepository.findAll();
    }

    /**
     * Credit (add money to) an account.
     *
     * VULNERABLE: same broken access control pattern as the rest of this
     * class - no check that the caller owns `id`, no upper bound on
     * `amount`, no audit trail. Try in Burp while logged in as alice (or
     * with no cookie at all):
     *   POST /account/1/credit?amount=100000
     */
    @PostMapping("/account/{id}/credit")
    @ResponseBody
    public Object credit(@PathVariable Long id, @RequestParam java.math.BigDecimal amount) {
        Optional<Account> accountOpt = accountRepository.findById(id);
        if (accountOpt.isEmpty()) return "Not found";
        Account account = accountOpt.get();
        account.setBalance(account.getBalance().add(amount));
        accountRepository.save(account);
        return account;
    }

    /**
     * Debit (remove money from) an account.
     *
     * VULNERABLE: same as credit() above, plus no balance-floor check, so
     * an account can be driven negative. Try in Burp:
     *   POST /account/1/debit?amount=100000
     */
    @PostMapping("/account/{id}/debit")
    @ResponseBody
    public Object debit(@PathVariable Long id, @RequestParam java.math.BigDecimal amount) {
        Optional<Account> accountOpt = accountRepository.findById(id);
        if (accountOpt.isEmpty()) return "Not found";
        Account account = accountOpt.get();
        account.setBalance(account.getBalance().subtract(amount));
        accountRepository.save(account);
        return account;
    }

    /**
     * Admin "edit user" form.
     *
     * VULNERABLE: same pattern as everywhere else in this app - reachable
     * by anyone who knows/guesses the URL, no check that the caller is
     * actually an admin (the dashboard just hides the link from non-admins
     * client-side; the endpoint itself enforces nothing).
     */
    @GetMapping("/admin/users/{id}/edit")
    public String editUserForm(@PathVariable Long id, Model model) {
        Optional<User> target = userRepository.findById(id);
        if (target.isEmpty()) return "redirect:/dashboard?user=admin";
        model.addAttribute("targetUser", target.get());
        return "admin-edit-user";
    }

    /**
     * VULNERABLE: updates any user's username/full name/role/password by
     * ID with no authorization check and no audit log. Role is a free-text
     * field here too, so a caller can promote any account (including their
     * own) straight to ADMIN - a privilege-escalation-by-design example to
     * pair with the IDOR findings above.
     */
    @PostMapping("/admin/users/{id}/edit")
    public String editUser(@PathVariable Long id,
                            @RequestParam String username,
                            @RequestParam String fullName,
                            @RequestParam String role,
                            @RequestParam(required = false) String password,
                            Model model) throws Exception {
        Optional<User> targetOpt = userRepository.findById(id);
        if (targetOpt.isEmpty()) return "redirect:/dashboard?user=admin";
        User target = targetOpt.get();
        target.setUsername(username);
        target.setFullName(fullName);
        target.setRole(role);
        if (password != null && !password.isBlank()) {
            target.setPassword(md5(password));
        }
        userRepository.save(target);
        return "redirect:/dashboard?user=admin";
    }

    private String md5(String input) throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(input.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
