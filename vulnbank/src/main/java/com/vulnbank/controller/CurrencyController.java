package com.vulnbank.controller;

import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;

/**
 * A10:2021 Server-Side Request Forgery (SSRF).
 */
@RestController
public class CurrencyController {

    /**
     * VULNERABLE: the server fetches whatever URL the client supplies,
     * with no allow-list, no blocking of private/internal IP ranges, and
     * no restriction on scheme. From Burp Repeater try:
     *   GET /currency/rate?source=http://169.254.169.254/latest/meta-data/
     * (cloud metadata endpoint - classic SSRF -> credential theft chain)
     * or point it at the app's own actuator/H2 console to pivot past a
     * network boundary that only allows requests from localhost.
     */
    @GetMapping("/currency/rate")
    public String fetchRate(@RequestParam String source) throws Exception {
        URL url = new URL(source); // no scheme/host allow-list at all
        URLConnection conn = url.openConnection();
        conn.setConnectTimeout(3000);
        conn.setReadTimeout(3000);
        StringBuilder result = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line).append("\n");
            }
        }
        return result.toString();
    }
}
