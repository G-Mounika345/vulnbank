package com.vulnbank.controller;

import com.vulnbank.model.Account;
import com.vulnbank.repository.AccountRepository;
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

    @GetMapping("/dashboard")
    public String dashboard(@RequestParam(required = false) String user, Model model) {
        model.addAttribute("username", user);
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
}
