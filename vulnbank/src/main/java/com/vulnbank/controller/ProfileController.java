package com.vulnbank.controller;

import org.springframework.web.bind.annotation.*;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;

/**
 * A05:2021 Security Misconfiguration (XXE - the XML parser is left with
 * its dangerous default features enabled: external entity resolution and
 * DOCTYPE processing are not disabled).
 *
 * OWASP now generally buckets classic XXE under A05, since the root cause
 * is a missing secure-by-default configuration on the XML parser.
 */
@RestController
public class ProfileController {

    /**
     * VULNERABLE: accepts arbitrary XML and parses it with a
     * DocumentBuilderFactory that has NOT had external entities disabled.
     * Try sending this as the body to POST /profile/import
     * (Content-Type: application/xml):
     *
     * <?xml version="1.0"?>
     * <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
     * <profile><bio>&xxe;</bio></profile>
     *
     * and watch the file contents get reflected back in the response.
     */
    @PostMapping(value = "/profile/import", consumes = "application/xml")
    public String importProfile(@RequestBody String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // Intentionally NOT calling:
        //   factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        //   factory.setExpandEntityReferences(false);
        // which is what a fix would add.
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new ByteArrayInputStream(xml.getBytes()));
        Element root = doc.getDocumentElement();
        return "Parsed profile, bio field = " + root.getTextContent();
    }
}
