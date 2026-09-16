package com.vulnbank.controller;

import com.vulnbank.model.Account;
import com.vulnbank.repository.AccountRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.util.Optional;

/**
 * A05:2021 Security Misconfiguration (CSRF disabled globally in
 * SecurityConfig) combined with A04:2021 Insecure Design (no re-auth /
 * confirmation step, no per-transaction limits, no rate limiting).
 */
@Controller
public class TransferController {

    @Autowired
    private AccountRepository accountRepository;

    /**
     * Because CSRF protection is off and the cookie has no SameSite
     * attribute, an attacker's page can auto-submit a hidden form to this
     * endpoint using the victim's browser session:
     *
     * <form action="http://localhost:8080/transfer" method="POST">
     *   <input name="fromId" value="1">
     *   <input name="toId" value="9">
     *   <input name="amount" value="5000">
     * </form>
     * <script>document.forms[0].submit()</script>
     *
     * Also notice: no check that the caller actually owns `fromId` (ties
     * back into A01 IDOR), and no upper bound on `amount`.
     */
    @PostMapping("/transfer")
    @ResponseBody
    public Object transfer(@RequestParam Long fromId,
                            @RequestParam Long toId,
                            @RequestParam BigDecimal amount) {
        Optional<Account> fromOpt = accountRepository.findById(fromId);
        Optional<Account> toOpt = accountRepository.findById(toId);
        if (fromOpt.isEmpty() || toOpt.isEmpty()) return "Invalid account(s)";

        Account from = fromOpt.get();
        Account to = toOpt.get();

        // No balance floor check -> can go negative; no max amount check.
        from.setBalance(from.getBalance().subtract(amount));
        to.setBalance(to.getBalance().add(amount));
        accountRepository.save(from);
        accountRepository.save(to);
        return "Transferred " + amount + " from " + from.getAccountNumber() + " to " + to.getAccountNumber();
    }
}
