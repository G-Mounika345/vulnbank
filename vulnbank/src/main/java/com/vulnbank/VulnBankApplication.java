package com.vulnbank;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * VulnBank - INTENTIONALLY VULNERABLE banking web app.
 *
 * Built purely for learning OWASP Top 10 (2021) exploitation with tools
 * like Burp Suite, in an isolated / local environment that you own.
 *
 * DO NOT deploy this to any shared, internet-facing, or production host.
 * DO NOT reuse any code/pattern here in a real application.
 */
@SpringBootApplication
public class VulnBankApplication {
    public static void main(String[] args) {
        SpringApplication.run(VulnBankApplication.class, args);
    }
}
