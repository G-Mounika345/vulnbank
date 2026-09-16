package com.vulnbank.controller;

import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * A01:2021 Broken Access Control (path traversal) + A04:2021 Insecure
 * Design (unrestricted file upload - no type/size/extension checks).
 */
@RestController
public class FileController {

    private static final String STATEMENT_DIR = "./statements/";
    private static final String UPLOAD_DIR = "./uploads/";

    /**
     * VULNERABLE: `filename` is concatenated straight into a filesystem
     * path with no sanitization. Try in Burp Repeater:
     *   GET /statements/download?filename=../../../../etc/passwd
     * (or on Windows targets, ..\..\..\..\Windows\win.ini)
     */
    @GetMapping("/statements/download")
    public ResponseEntity<Resource> download(@RequestParam String filename) throws IOException {
        File dir = new File(STATEMENT_DIR);
        if (!dir.exists()) dir.mkdirs();
        File sample = new File(dir, "january.txt");
        if (!sample.exists()) Files.write(sample.toPath(), "Statement: no transactions.".getBytes());

        File target = new File(STATEMENT_DIR + filename); // <-- path traversal
        Resource resource = new FileSystemResource(target);
        return ResponseEntity.ok(resource);
    }

    /**
     * VULNERABLE: no check on file extension, MIME type, or content -
     * an attacker can upload a .jsp/.war/executable script if the
     * container ever serves this directory, or use it to store phishing
     * pages. Also no size limit -> trivial DoS vector.
     */
    @PostMapping("/profile/upload-picture")
    public String upload(@RequestParam("file") MultipartFile file) throws IOException {
        File dir = new File(UPLOAD_DIR);
        if (!dir.exists()) dir.mkdirs();
        // Filename taken verbatim from the client, including its path
        // separators - another traversal angle, this time on write.
        File dest = new File(UPLOAD_DIR + file.getOriginalFilename());
        file.transferTo(dest);
        return "Uploaded to " + dest.getPath();
    }
}
