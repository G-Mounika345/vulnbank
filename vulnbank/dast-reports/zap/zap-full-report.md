# ZAP by Checkmarx Scanning Report

ZAP by [Checkmarx](https://checkmarx.com/).


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 5 |
| Medium | 6 |
| Low | 0 |
| Informational | 7 |




## Insights

| Level | Reason | Site | Description | Statistic |
| --- | --- | --- | --- | --- |
| Low | Warning |  | ZAP warnings logged - see the zap.log file for details | 16    |
| Info | Informational | http://host.docker.internal:8080 | Percentage of responses with status code 2xx | 56 % |
| Info | Informational | http://host.docker.internal:8080 | Percentage of responses with status code 3xx | 1 % |
| Info | Informational | http://host.docker.internal:8080 | Percentage of responses with status code 4xx | 34 % |
| Info | Informational | http://host.docker.internal:8080 | Percentage of responses with status code 5xx | 6 % |
| Info | Informational | http://host.docker.internal:8080 | Percentage of endpoints with content type application/json | 45 % |
| Info | Informational | http://host.docker.internal:8080 | Percentage of endpoints with content type text/html | 34 % |
| Info | Informational | http://host.docker.internal:8080 | Percentage of endpoints with content type text/plain | 2 % |
| Info | Informational | http://host.docker.internal:8080 | Percentage of endpoints with method GET | 82 % |
| Info | Informational | http://host.docker.internal:8080 | Percentage of endpoints with method POST | 17 % |
| Info | Informational | http://host.docker.internal:8080 | Count of total endpoints | 35    |
| Info | Informational | http://host.docker.internal:8080 | Percentage of slow responses | 18 % |







## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- |
| Cross Site Scripting (Persistent) | High | 1 |
| Cross Site Scripting (Reflected) | High | 2 |
| Path Traversal | High | 1 |
| Remote File Inclusion | High | 1 |
| SQL Injection | High | 2 |
| Absence of Anti-CSRF Tokens | Medium | Systemic |
| Buffer Overflow | Medium | 16 |
| Content Security Policy (CSP) Header Not Set | Medium | Systemic |
| Format String Error | Medium | 1 |
| Missing Anti-clickjacking Header | Medium | Systemic |
| Parameter Tampering | Medium | 3 |
| Authentication Request Identified | Informational | 5 |
| GET for POST | Informational | 1 |
| Information Disclosure - Sensitive Information in URL | Informational | 1 |
| Modern Web Application | Informational | 3 |
| User Agent Fuzzer | Informational | Systemic |
| User Controllable HTML Element Attribute (Potential XSS) | Informational | 1 |
| Username Hash Found | Informational | 2 |




## Alert Detail



### [ Cross Site Scripting (Persistent) ](https://www.zaproxy.org/docs/alerts/40014/)



##### High (Medium)

### Description

Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's browser instance. A browser instance can be a standard web browser client, or a browser object embedded in a software product such as the browser within WinAmp, an RSS reader, or an email client. The code itself is usually written in HTML/JavaScript, but may also extend to VBScript, ActiveX, Java, Flash, or any other browser-supported technology.
When an attacker gets a user's browser to execute his/her code, the code will run within the security context (or zone) of the hosting web site. With this level of privilege, the code has the ability to read, modify and transmit any sensitive data accessible by the browser. A Cross-site Scripted user could have his/her account hijacked (cookie theft), their browser redirected to another location, or possibly shown fraudulent content delivered by the web site they are visiting. Cross-site Scripting attacks essentially compromise the trust relationship between a user and the web site. Applications utilizing browser object instances which load content from the file system may execute code under the local machine zone allowing for system compromise.

There are three types of Cross-site Scripting attacks: non-persistent, persistent and DOM-based.
Non-persistent attacks and DOM-based attacks require a user to either visit a specially crafted link laced with malicious code, or visit a malicious web page containing a web form, which when posted to the vulnerable site, will mount the attack. Using a malicious form will oftentimes take place when the vulnerable resource only accepts HTTP POST requests. In such a case, the form can be submitted automatically, without the victim's knowledge (e.g. by using JavaScript). Upon clicking on the malicious link or submitting the malicious form, the XSS payload will get echoed back and will get interpreted by the user's browser and execute. Another technique to send almost arbitrary requests (GET and POST) is by using an embedded client, such as Adobe Flash.
Persistent attacks occur when the malicious code is submitted to a web site where it's stored for a period of time. Examples of an attacker's favorite targets often include message board posts, web mail messages, and web chat software. The unsuspecting user is not required to interact with any additional site/link (e.g. an attacker site or a malicious link sent via email), just simply view the web page containing the code.

* URL: http://host.docker.internal:8080/messages
  * Node Name: `http://host.docker.internal:8080/messages`
  * Method: `GET`
  * Parameter: `content`
  * Attack: `</b><script>alert(1);</script><b>`
  * Evidence: ``
  * Other Info: `Source URL: http://host.docker.internal:8080/messages`


Instances: 1

### Solution

Phase: Architecture and Design
Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.
Examples of libraries and frameworks that make it easier to generate properly encoded output include Microsoft's Anti-XSS library, the OWASP ESAPI Encoding module, and Apache Wicket.

Phases: Implementation; Architecture and Design
Understand the context in which your data will be used and the encoding that will be expected. This is especially important when transmitting data between different components, or when generating outputs that can contain multiple encodings at the same time, such as web pages or multi-part mail messages. Study all expected communication protocols and data representations to determine the required encoding strategies.
For any data that will be output to another web page, especially any data that was received from external inputs, use the appropriate encoding on all non-alphanumeric characters.
Consult the XSS Prevention Cheat Sheet for more details on the types of encoding and escaping that are needed.

Phase: Architecture and Design
For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side, in order to avoid CWE-602. Attackers can bypass the client-side checks by modifying values after the checks have been performed, or by changing the client to remove the client-side checks entirely. Then, these modified values would be submitted to the server.

If available, use structured mechanisms that automatically enforce the separation between data and code. These mechanisms may be able to provide the relevant quoting, encoding, and validation automatically, instead of relying on the developer to provide this capability at every point where output is generated.

Phase: Implementation
For every web page that is generated, use and specify a character encoding such as ISO-8859-1 or UTF-8. When an encoding is not specified, the web browser may choose a different encoding by guessing which encoding is actually being used by the web page. This can cause the web browser to treat certain sequences as special, opening up the client to subtle XSS attacks. See CWE-116 for more mitigations related to encoding/escaping.

To help mitigate XSS attacks against the user's session cookie, set the session cookie to be HttpOnly. In browsers that support the HttpOnly feature (such as more recent versions of Internet Explorer and Firefox), this attribute can prevent the user's session cookie from being accessible to malicious client-side scripts that use document.cookie. This is not a complete solution, since HttpOnly is not supported by all browsers. More importantly, XMLHTTPRequest and other powerful browser technologies provide read access to HTTP headers, including the Set-Cookie header in which the HttpOnly flag is set.

Assume all input is malicious. Use an "accept known good" input validation strategy, i.e., use an allow list of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to specifications, or transform it into something that does. Do not rely exclusively on looking for malicious or malformed inputs (i.e., do not rely on a deny list). However, deny lists can be useful for detecting potential attacks or determining which inputs are so malformed that they should be rejected outright.

When performing input validation, consider all potentially relevant properties, including length, type of input, the full range of acceptable values, missing or extra inputs, syntax, consistency across related fields, and conformance to business rules. As an example of business rule logic, "boat" may be syntactically valid because it only contains alphanumeric characters, but it is not valid if you are expecting colors such as "red" or "blue."

Ensure that you perform input validation at well-defined interfaces within the application. This will help protect the application even if a component is reused or moved elsewhere.
	

### Reference


* [ https://owasp.org/www-community/attacks/xss/ ](https://owasp.org/www-community/attacks/xss/)
* [ https://cwe.mitre.org/data/definitions/79.html ](https://cwe.mitre.org/data/definitions/79.html)


#### CWE Id: [ 79 ](https://cwe.mitre.org/data/definitions/79.html)


#### WASC Id: 8

#### Source ID: 1

### [ Cross Site Scripting (Reflected) ](https://www.zaproxy.org/docs/alerts/40012/)



##### High (Medium)

### Description

Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's browser instance. A browser instance can be a standard web browser client, or a browser object embedded in a software product such as the browser within WinAmp, an RSS reader, or an email client. The code itself is usually written in HTML/JavaScript, but may also extend to VBScript, ActiveX, Java, Flash, or any other browser-supported technology.
When an attacker gets a user's browser to execute his/her code, the code will run within the security context (or zone) of the hosting web site. With this level of privilege, the code has the ability to read, modify and transmit any sensitive data accessible by the browser. A Cross-site Scripted user could have his/her account hijacked (cookie theft), their browser redirected to another location, or possibly shown fraudulent content delivered by the web site they are visiting. Cross-site Scripting attacks essentially compromise the trust relationship between a user and the web site. Applications utilizing browser object instances which load content from the file system may execute code under the local machine zone allowing for system compromise.

There are three types of Cross-site Scripting attacks: non-persistent, persistent and DOM-based.
Non-persistent attacks and DOM-based attacks require a user to either visit a specially crafted link laced with malicious code, or visit a malicious web page containing a web form, which when posted to the vulnerable site, will mount the attack. Using a malicious form will oftentimes take place when the vulnerable resource only accepts HTTP POST requests. In such a case, the form can be submitted automatically, without the victim's knowledge (e.g. by using JavaScript). Upon clicking on the malicious link or submitting the malicious form, the XSS payload will get echoed back and will get interpreted by the user's browser and execute. Another technique to send almost arbitrary requests (GET and POST) is by using an embedded client, such as Adobe Flash.
Persistent attacks occur when the malicious code is submitted to a web site where it's stored for a period of time. Examples of an attacker's favorite targets often include message board posts, web mail messages, and web chat software. The unsuspecting user is not required to interact with any additional site/link (e.g. an attacker site or a malicious link sent via email), just simply view the web page containing the code.

* URL: http://host.docker.internal:8080/search%3Fq=%253C%252Fspan%253E%253CscrIpt%253Ealert%25281%2529%253B%253C%252FscRipt%253E%253Cspan%253E
  * Node Name: `http://host.docker.internal:8080/search (q)`
  * Method: `GET`
  * Parameter: `q`
  * Attack: `</span><scrIpt>alert(1);</scRipt><span>`
  * Evidence: `</span><scrIpt>alert(1);</scRipt><span>`
  * Other Info: ``
* URL: http://host.docker.internal:8080/messages
  * Node Name: `http://host.docker.internal:8080/messages ()(content,sender)`
  * Method: `POST`
  * Parameter: `content`
  * Attack: `</span><scrIpt>alert(1);</scRipt><span>`
  * Evidence: `</span><scrIpt>alert(1);</scRipt><span>`
  * Other Info: ``


Instances: 2

### Solution

Phase: Architecture and Design
Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.
Examples of libraries and frameworks that make it easier to generate properly encoded output include Microsoft's Anti-XSS library, the OWASP ESAPI Encoding module, and Apache Wicket.

Phases: Implementation; Architecture and Design
Understand the context in which your data will be used and the encoding that will be expected. This is especially important when transmitting data between different components, or when generating outputs that can contain multiple encodings at the same time, such as web pages or multi-part mail messages. Study all expected communication protocols and data representations to determine the required encoding strategies.
For any data that will be output to another web page, especially any data that was received from external inputs, use the appropriate encoding on all non-alphanumeric characters.
Consult the XSS Prevention Cheat Sheet for more details on the types of encoding and escaping that are needed.

Phase: Architecture and Design
For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side, in order to avoid CWE-602. Attackers can bypass the client-side checks by modifying values after the checks have been performed, or by changing the client to remove the client-side checks entirely. Then, these modified values would be submitted to the server.

If available, use structured mechanisms that automatically enforce the separation between data and code. These mechanisms may be able to provide the relevant quoting, encoding, and validation automatically, instead of relying on the developer to provide this capability at every point where output is generated.

Phase: Implementation
For every web page that is generated, use and specify a character encoding such as ISO-8859-1 or UTF-8. When an encoding is not specified, the web browser may choose a different encoding by guessing which encoding is actually being used by the web page. This can cause the web browser to treat certain sequences as special, opening up the client to subtle XSS attacks. See CWE-116 for more mitigations related to encoding/escaping.

To help mitigate XSS attacks against the user's session cookie, set the session cookie to be HttpOnly. In browsers that support the HttpOnly feature (such as more recent versions of Internet Explorer and Firefox), this attribute can prevent the user's session cookie from being accessible to malicious client-side scripts that use document.cookie. This is not a complete solution, since HttpOnly is not supported by all browsers. More importantly, XMLHTTPRequest and other powerful browser technologies provide read access to HTTP headers, including the Set-Cookie header in which the HttpOnly flag is set.

Assume all input is malicious. Use an "accept known good" input validation strategy, i.e., use an allow list of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to specifications, or transform it into something that does. Do not rely exclusively on looking for malicious or malformed inputs (i.e., do not rely on a deny list). However, deny lists can be useful for detecting potential attacks or determining which inputs are so malformed that they should be rejected outright.

When performing input validation, consider all potentially relevant properties, including length, type of input, the full range of acceptable values, missing or extra inputs, syntax, consistency across related fields, and conformance to business rules. As an example of business rule logic, "boat" may be syntactically valid because it only contains alphanumeric characters, but it is not valid if you are expecting colors such as "red" or "blue."

Ensure that you perform input validation at well-defined interfaces within the application. This will help protect the application even if a component is reused or moved elsewhere.
	

### Reference


* [ https://owasp.org/www-community/attacks/xss/ ](https://owasp.org/www-community/attacks/xss/)
* [ https://cwe.mitre.org/data/definitions/79.html ](https://cwe.mitre.org/data/definitions/79.html)


#### CWE Id: [ 79 ](https://cwe.mitre.org/data/definitions/79.html)


#### WASC Id: 8

#### Source ID: 1

### [ Path Traversal ](https://www.zaproxy.org/docs/alerts/6/)



##### High (Medium)

### Description

The Path Traversal attack technique allows an attacker access to files, directories, and commands that potentially reside outside the web document root directory. An attacker may manipulate a URL in such a way that the web site will execute or reveal the contents of arbitrary files anywhere on the web server. Any device that exposes an HTTP-based interface is potentially vulnerable to Path Traversal.

Most web sites restrict user access to a specific portion of the file-system, typically called the "web document root" or "CGI root" directory. These directories contain the files intended for user access and the executable necessary to drive web application functionality. To access files or execute commands anywhere on the file-system, Path Traversal attacks will utilize the ability of special-characters sequences.

The most basic Path Traversal attack uses the "../" special-character sequence to alter the resource location requested in the URL. Although most popular web servers will prevent this technique from escaping the web document root, alternate encodings of the "../" sequence may help bypass the security filters. These method variations include valid and invalid Unicode-encoding ("..%u2216" or "..%c0%af") of the forward slash character, backslash characters ("..\") on Windows-based servers, URL encoded characters "%2e%2e%2f"), and double URL encoding ("..%255c") of the backslash character.

Even if the web server properly restricts Path Traversal attempts in the URL path, a web application itself may still be vulnerable due to improper handling of user-supplied input. This is a common problem of web applications that use template mechanisms or load static text from files. In variations of the attack, the original URL parameter value is substituted with the file name of one of the web application's dynamic scripts. Consequently, the results can reveal source code because the file is interpreted as text instead of an executable script. These techniques often employ additional special characters such as the dot (".") to reveal the listing of the current working directory, or "%00" NULL characters in order to bypass rudimentary file extension checks.

* URL: http://host.docker.internal:8080/statements/download%3Ffilename=..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252FWindows%252Fsystem.ini
  * Node Name: `http://host.docker.internal:8080/statements/download (filename)`
  * Method: `GET`
  * Parameter: `filename`
  * Attack: `../../../../../../../../../../../../../../../../Windows/system.ini`
  * Evidence: `[drivers]`
  * Other Info: ``


Instances: 1

### Solution

Assume all input is malicious. Use an "accept known good" input validation strategy, i.e., use an allow list of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to specifications, or transform it into something that does. Do not rely exclusively on looking for malicious or malformed inputs (i.e., do not rely on a deny list). However, deny lists can be useful for detecting potential attacks or determining which inputs are so malformed that they should be rejected outright.

When performing input validation, consider all potentially relevant properties, including length, type of input, the full range of acceptable values, missing or extra inputs, syntax, consistency across related fields, and conformance to business rules. As an example of business rule logic, "boat" may be syntactically valid because it only contains alphanumeric characters, but it is not valid if you are expecting colors such as "red" or "blue."

For filenames, use stringent allow lists that limit the character set to be used. If feasible, only allow a single "." character in the filename to avoid weaknesses, and exclude directory separators such as "/". Use an allow list of allowable file extensions.

Warning: if you attempt to cleanse your data, then do so that the end result is not in the form that can be dangerous. A sanitizing mechanism can remove characters such as '.' and ';' which may be required for some exploits. An attacker can try to fool the sanitizing mechanism into "cleaning" data into a dangerous form. Suppose the attacker injects a '.' inside a filename (e.g. "sensi.tiveFile") and the sanitizing mechanism removes the character resulting in the valid filename, "sensitiveFile". If the input data are now assumed to be safe, then the file may be compromised. 

Inputs should be decoded and canonicalized to the application's current internal representation before being validated. Make sure that your application does not decode the same input twice. Such errors could be used to bypass allow list schemes by introducing dangerous inputs after they have been checked.

Use a built-in path canonicalization function (such as realpath() in C) that produces the canonical version of the pathname, which effectively removes ".." sequences and symbolic links.

Run your code using the lowest privileges that are required to accomplish the necessary tasks. If possible, create isolated accounts with limited privileges that are only used for a single task. That way, a successful attack will not immediately give the attacker access to the rest of the software or its environment. For example, database applications rarely need to run as the database administrator, especially in day-to-day operations.

When the set of acceptable objects, such as filenames or URLs, is limited or known, create a mapping from a set of fixed input values (such as numeric IDs) to the actual filenames or URLs, and reject all other inputs.

Run your code in a "jail" or similar sandbox environment that enforces strict boundaries between the process and the operating system. This may effectively restrict which files can be accessed in a particular directory or which commands can be executed by your software.

OS-level examples include the Unix chroot jail, AppArmor, and SELinux. In general, managed code may provide some protection. For example, java.io.FilePermission in the Java SecurityManager allows you to specify restrictions on file operations.

This may not be a feasible solution, and it only limits the impact to the operating system; the rest of your application may still be subject to compromise.


### Reference


* [ https://owasp.org/www-community/attacks/Path_Traversal ](https://owasp.org/www-community/attacks/Path_Traversal)
* [ https://cwe.mitre.org/data/definitions/22.html ](https://cwe.mitre.org/data/definitions/22.html)


#### CWE Id: [ 22 ](https://cwe.mitre.org/data/definitions/22.html)


#### WASC Id: 33

#### Source ID: 1

### [ Remote File Inclusion ](https://www.zaproxy.org/docs/alerts/7/)



##### High (Medium)

### Description

Remote File Include (RFI) is an attack technique used to exploit "dynamic file include" mechanisms in web applications. When web applications take user input (URL, parameter value, etc.) and pass them into file include commands, the web application might be tricked into including remote files with malicious code.

Almost all web application frameworks support file inclusion. File inclusion is mainly used for packaging common code into separate files that are later referenced by main application modules. When a web application references an include file, the code in this file may be executed implicitly or explicitly by calling specific procedures. If the choice of module to load is based on elements from the HTTP request, the web application might be vulnerable to RFI.
An attacker can use RFI for:
    * Running malicious code on the server: any code in the included malicious files will be run by the server. If the file include is not executed using some wrapper, code in include files is executed in the context of the server user. This could lead to a complete system compromise.
    * Running malicious code on clients: the attacker's malicious code can manipulate the content of the response sent to the client. The attacker can embed malicious code in the response that will be run by the client (for example, JavaScript to steal the client session cookies).

PHP is particularly vulnerable to RFI attacks due to the extensive use of "file includes" in PHP programming and due to default server configurations that increase susceptibility to an RFI attack.

* URL: http://host.docker.internal:8080/currency/rate%3Fsource=http%253A%252F%252Fwww.google.com%252F
  * Node Name: `http://host.docker.internal:8080/currency/rate (source)`
  * Method: `GET`
  * Parameter: `source`
  * Attack: `http://www.google.com/`
  * Evidence: `<title>Google</title>`
  * Other Info: ``


Instances: 1

### Solution

Phase: Architecture and Design
When the set of acceptable objects, such as filenames or URLs, is limited or known, create a mapping from a set of fixed input values (such as numeric IDs) to the actual filenames or URLs, and reject all other inputs.
For example, ID 1 could map to "inbox.txt" and ID 2 could map to "profile.txt". Features such as the ESAPI AccessReferenceMap provide this capability.

Phases: Architecture and Design; Operation
Run your code in a "jail" or similar sandbox environment that enforces strict boundaries between the process and the operating system. This may effectively restrict which files can be accessed in a particular directory or which commands can be executed by your software.
OS-level examples include the Unix chroot jail, AppArmor, and SELinux. In general, managed code may provide some protection. For example, java.io.FilePermission in the Java SecurityManager allows you to specify restrictions on file operations.
This may not be a feasible solution, and it only limits the impact to the operating system; the rest of your application may still be subject to compromise.
Be careful to avoid CWE-243 and other weaknesses related to jails.
For PHP, the interpreter offers restrictions such as open basedir or safe mode which can make it more difficult for an attacker to escape out of the application. Also consider Suhosin, a hardened PHP extension, which includes various options that disable some of the more dangerous PHP features.

Phase: Implementation
Assume all input is malicious. Use an "accept known good" input validation strategy, i.e., use an allow list of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to specifications, or transform it into something that does. Do not rely exclusively on looking for malicious or malformed inputs (i.e., do not rely on a deny list). However, deny lists can be useful for detecting potential attacks or determining which inputs are so malformed that they should be rejected outright.
When performing input validation, consider all potentially relevant properties, including length, type of input, the full range of acceptable values, missing or extra inputs, syntax, consistency across related fields, and conformance to business rules. As an example of business rule logic, "boat" may be syntactically valid because it only contains alphanumeric characters, but it is not valid if you are expecting colors such as "red" or "blue."
For filenames, use stringent allow lists that limit the character set to be used. If feasible, only allow a single "." character in the filename to avoid weaknesses such as CWE-23, and exclude directory separators such as "/" to avoid CWE-36. Use an allow list of allowable file extensions, which will help to avoid CWE-434.

Phases: Architecture and Design; Operation
Store library, include, and utility files outside of the web document root, if possible. Otherwise, store them in a separate directory and use the web server's access control capabilities to prevent attackers from directly requesting them. One common practice is to define a fixed constant in each calling program, then check for the existence of the constant in the library/include file; if the constant does not exist, then the file was directly requested, and it can exit immediately.
This significantly reduces the chance of an attacker being able to bypass any protection mechanisms that are in the base program but not in the include files. It will also reduce your attack surface.

Phases: Architecture and Design; Implementation
Understand all the potential areas where untrusted inputs can enter your software: parameters or arguments, cookies, anything read from the network, environment variables, reverse DNS lookups, query results, request headers, URL components, e-mail, files, databases, and any external systems that provide data to the application. Remember that such inputs may be obtained indirectly through API calls.
Many file inclusion problems occur because the programmer assumed that certain inputs could not be modified, especially for cookies and URL components.

### Reference


* [ https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion ](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion)
* [ https://cwe.mitre.org/data/definitions/98.html ](https://cwe.mitre.org/data/definitions/98.html)


#### CWE Id: [ 98 ](https://cwe.mitre.org/data/definitions/98.html)


#### WASC Id: 5

#### Source ID: 1

### [ SQL Injection ](https://www.zaproxy.org/docs/alerts/40018/)



##### High (Low)

### Description

SQL injection may be possible.

* URL: http://host.docker.internal:8080/dashboard%3Fuser=%2527
  * Node Name: `http://host.docker.internal:8080/dashboard (user)`
  * Method: `GET`
  * Parameter: `user`
  * Attack: `'`
  * Evidence: `HTTP/1.1 500`
  * Other Info: ``
* URL: http://host.docker.internal:8080/login
  * Node Name: `http://host.docker.internal:8080/login ()(password,username)`
  * Method: `POST`
  * Parameter: `username`
  * Attack: `'`
  * Evidence: `HTTP/1.1 500`
  * Other Info: ``


Instances: 2

### Solution

Do not trust client side input, even if there is client side validation in place.
In general, type check all data on the server side.
If the application uses JDBC, use PreparedStatement or CallableStatement, with parameters passed by '?'
If the application uses ASP, use ADO Command Objects with strong type checking and parameterized queries.
If database Stored Procedures can be used, use them.
Do *not* concatenate strings into queries in the stored procedure, or use 'exec', 'exec immediate', or equivalent functionality!
Do not create dynamic SQL queries using simple string concatenation.
Escape all data received from the client.
Apply an 'allow list' of allowed characters, or a 'deny list' of disallowed characters in user input.
Apply the principle of least privilege by using the least privileged database user possible.
In particular, avoid using the 'sa' or 'db-owner' database users. This does not eliminate SQL injection, but minimizes its impact.
Grant the minimum database access that is necessary for the application.

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)


#### CWE Id: [ 89 ](https://cwe.mitre.org/data/definitions/89.html)


#### WASC Id: 19

#### Source ID: 1

### [ Absence of Anti-CSRF Tokens ](https://www.zaproxy.org/docs/alerts/10202/)



##### Medium (Low)

### Description

No Anti-CSRF tokens were found in a HTML submission form.
A cross-site request forgery is an attack that involves forcing a victim to send an HTTP request to a target destination without their knowledge or intent in order to perform an action as the victim. The underlying cause is application functionality using predictable URL/form actions in a repeatable way. The nature of the attack is that CSRF exploits the trust that a web site has for a user. By contrast, cross-site scripting (XSS) exploits the trust that a user has for a web site. Like XSS, CSRF attacks are not necessarily cross-site, but they can be. Cross-site request forgery is also known as CSRF, XSRF, one-click attack, session riding, confused deputy, and sea surf.

CSRF attacks are effective in a number of situations, including:
    * The victim has an active session on the target site.
    * The victim is authenticated via HTTP auth on the target site.
    * The victim is on the same local network as the target site.

CSRF has primarily been used to perform an action against a target site using the victim's privileges, but recent techniques have been discovered to disclose information by gaining access to the response. The risk of information disclosure is dramatically increased when the target site is vulnerable to XSS, because XSS can be used as a platform for CSRF, allowing the attack to operate within the bounds of the same-origin policy.

* URL: http://host.docker.internal:8080/admin/users/1/edit
  * Node Name: `http://host.docker.internal:8080/admin/users/1/edit`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<form method="post" action="/admin/users/1/edit">`
  * Other Info: `No known Anti-CSRF token [anticsrf, CSRFToken, __RequestVerificationToken, csrfmiddlewaretoken, authenticity_token, OWASP_CSRFTOKEN, anoncsrf, csrf_token, _csrf, _csrfSecret, __csrf_magic, CSRF, _token, _csrf_token, _csrfToken] was found in the following HTML form: [Form 1: "fullName" "password" "username" ].`
* URL: http://host.docker.internal:8080/admin/users/2/edit
  * Node Name: `http://host.docker.internal:8080/admin/users/2/edit`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<form method="post" action="/admin/users/2/edit">`
  * Other Info: `No known Anti-CSRF token [anticsrf, CSRFToken, __RequestVerificationToken, csrfmiddlewaretoken, authenticity_token, OWASP_CSRFTOKEN, anoncsrf, csrf_token, _csrf, _csrfSecret, __csrf_magic, CSRF, _token, _csrf_token, _csrfToken] was found in the following HTML form: [Form 1: "fullName" "password" "username" ].`
* URL: http://host.docker.internal:8080/login
  * Node Name: `http://host.docker.internal:8080/login`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<form method="post" action="/login">`
  * Other Info: `No known Anti-CSRF token [anticsrf, CSRFToken, __RequestVerificationToken, csrfmiddlewaretoken, authenticity_token, OWASP_CSRFTOKEN, anoncsrf, csrf_token, _csrf, _csrfSecret, __csrf_magic, CSRF, _token, _csrf_token, _csrfToken] was found in the following HTML form: [Form 1: "password" "username" ].`
* URL: http://host.docker.internal:8080/login%3Flogout
  * Node Name: `http://host.docker.internal:8080/login (logout)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<form method="post" action="/login">`
  * Other Info: `No known Anti-CSRF token [anticsrf, CSRFToken, __RequestVerificationToken, csrfmiddlewaretoken, authenticity_token, OWASP_CSRFTOKEN, anoncsrf, csrf_token, _csrf, _csrfSecret, __csrf_magic, CSRF, _token, _csrf_token, _csrfToken] was found in the following HTML form: [Form 1: "password" "username" ].`
* URL: http://host.docker.internal:8080/messages
  * Node Name: `http://host.docker.internal:8080/messages`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<form method="post" action="/messages">`
  * Other Info: `No known Anti-CSRF token [anticsrf, CSRFToken, __RequestVerificationToken, csrfmiddlewaretoken, authenticity_token, OWASP_CSRFTOKEN, anoncsrf, csrf_token, _csrf, _csrfSecret, __csrf_magic, CSRF, _token, _csrf_token, _csrfToken] was found in the following HTML form: [Form 1: "content" "sender" ].`

Instances: Systemic


### Solution

Phase: Architecture and Design
Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.
For example, use anti-CSRF packages such as the OWASP CSRFGuard.

Phase: Implementation
Ensure that your application is free of cross-site scripting issues, because most CSRF defenses can be bypassed using attacker-controlled script.

Phase: Architecture and Design
Generate a unique nonce for each form, place the nonce into the form, and verify the nonce upon receipt of the form. Be sure that the nonce is not predictable (CWE-330).
Note that this can be bypassed using XSS.

Identify especially dangerous operations. When the user performs a dangerous operation, send a separate confirmation request to ensure that the user intended to perform that operation.
Note that this can be bypassed using XSS.

Use the ESAPI Session Management control.
This control includes a component for CSRF.

Do not use the GET method for any request that triggers a state change.

Phase: Implementation
Check the HTTP Referer header to see if the request originated from an expected page. This could break legitimate functionality, because users or proxies may have disabled sending the Referer for privacy reasons.

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
* [ https://cwe.mitre.org/data/definitions/352.html ](https://cwe.mitre.org/data/definitions/352.html)


#### CWE Id: [ 352 ](https://cwe.mitre.org/data/definitions/352.html)


#### WASC Id: 9

#### Source ID: 3

### [ Buffer Overflow ](https://www.zaproxy.org/docs/alerts/30001/)



##### Medium (Medium)

### Description

Buffer overflow errors are characterized by the overwriting of memory spaces of the background web process, which should have never been modified intentionally or unintentionally. Overwriting values of the IP (Instruction Pointer), BP (Base Pointer) and other registers causes exceptions, segmentation faults, and other process errors to occur. Usually these errors end execution of the application in an unexpected way.

* URL: http://host.docker.internal:8080/currency/rate%3Fsource=http://example.com
  * Node Name: `http://host.docker.internal:8080/currency/rate (source)`
  * Method: `GET`
  * Parameter: `source`
  * Attack: `wUEoUMtFPWcKZpjuhjhlfHrZMXOxBFSXHgCIrYtFZpLvrNgwfyQkXLymVkDypwbycOfCfdKhEKMVLvNZyfAaqYljXsuwBMZqHIupkRhioCrYAAZKkELJkOBPANYpdMZpnFUenXXdvJXhaYxtPYjFeVTQoUgGBPSlJbIwtrqbYcXKYYhecDHtsEZIYaARFPTBdsixWSLlJPqdVFocxGlcvworoNGvulcklPwXcMSwIcloincJQadELfWjZxQPxxEELnYkCsoxxThLqPAEolGxfndAHLnGfRdQaPjXFpEfHolZVFwZxyWZtcRblauxTWQhBmCplHInHmyhkiHnlSlAgNExJNyyqMAOmZPiuDThbsvRrZwCOKZtTSRXwLmuGlvEAmbQAwCTFsMmcBftbLqYmUMZmLIccrVsOrYFxlugJlFRGGjrCJASgipaPyTTPvUTxhdremVLSTKMoOXajHpCVVwjTDlBdXpvMVnRNfoqMgJVMhgkkvClSCDBAvGwQlGPfsXBSHESttKoEIjAUCsvwWsxagUEDnqhhMXpNsvZUOJKmSCXxoNwQmoQsoQPTdbfBJwHVYdfVoNEofdyuMHQkywNJJKsBMCnqfOOfwkIqxGQeMObqfKYehSyTxbFQRIpQefSfBZALklSeEYPTKiMtGSuCkeEjBjMQrtIJAfPmoBGqWDifapArqVNpqFdJhgOmAKkaunYjoQdcvLkhJfUmhQCXRmCkNvsHjydOMsYlVPPxKSKFJFRBmLwGfJlnCDInoIWcSPhhUPmimYMBAkacAvaQMqoBDRvRobBxGtoGujxbKagmhDWVfHFkqalcYxcjMtnDUCFiRFipuiXUntxDtYmGFDViifGFWpBpncfXvhtcwVKgEiOIkNQGGYiTiVoskUiWayUqNtVDqVIhbZNxkauUeXPNOQiYDndxbrwRqnnybTiMCCwRTynQufpQDdGBhuLissyuSsavJZZAwRKSmfZApinEBRWbjxSUmyEsGKmZRKgTSFCYhAfmRljpcIZDoltUhqVnGLdLlyrDxgYgprQPtxyvhuCdwWdHDDZEMVtJgERxkxyPgsjqNWiLQniwIrZySqcAyRiPIePgggevLZpPQUaDSmMYCHcrcYwQtUvaLlZFWjrJYbnasPbXwvivDxjNbpwLmtFroXKGmRIXSxGmKbyIOkApcTIIukumMBuLoFUdrrZbZRIejAfuYLIIhosEqMEWVDCyoYcBkytHdyxyOMPhEWfYnQWfoZIoOhnBWlvEPHQIOvNTRfEZJlNJitJTckdmFdIvkafJFkAWtObSCcbNZhvQdgaUvZuLcGKuOnqqqqwdQVAdSRQjeDXNcHShvVeBbRZdIMegSHjJdKYsBqtwJOJYTFnEQxXyGufdUsTCsPbunPcsgtkybEsFQiCTuNysktccLnKfsKWdISZbGsfKVRuLLKsAkmcXFTMYULpufEXBSnmjmcxLmSxCSVHSIHlgcQlaOExJlYcewigxdFrInLIoftoybnPDuEWCCCHdZoCNeNlLnWFvgVUqWDHauaIwcabOcEiUfsgTBCPBhsMSnxGvtDHgNxwUgDJWmqGdFERCbbnkrcwWgchitWGymhEAoywwNwwrUodjgBxWKEMXGWOVONfreXssILRDHYWoWYbxfhkPuHwFHXpQPOVVFMCMeFcrPkbcVuHMuIPVkWSnamSkmqhphruwAoMxZXAGsHjHDhHwIGbvpvGrUUwFZTbVZgcEAnVCeiUYvrabHxhVNlnTicVsfPhcIAoxLmhtDoHsbqpidoLdLrGUEGjQRciPmFXLFijrHNIcRXfvTrGKQfgNFqikwgvItieLRmjkOcKxBDWVhXKACVIqIphdNlRwWNAmWQnJNRrRuIswUHmOVVemoqkWSZfbTsXMgyhhsgRJqKnNvvyJnCvffFHxWftQoOjVTQsjjvtvodarCkKApMftZXCPnYHcbLPEqkmsgVTIVnUlLoquwTJUwycgEVnfBBsnoCPiLhIEoSqUDACoLokdUBTNAncwFZFGSIuEIVyjDeaOPPQPGyABTyIXiZANVPemsHnbOaJFDDuFesSwlfWiNsafbRjKVIBSHmXMJbX`
  * Evidence: `Connection: close`
  * Other Info: `Potential Buffer Overflow. The script closed the connection and threw a 500 Internal Server Error.`
* URL: http://host.docker.internal:8080/statements/download%3Ffilename=january.txt
  * Node Name: `http://host.docker.internal:8080/statements/download (filename)`
  * Method: `GET`
  * Parameter: `filename`
  * Attack: `lRuLYQtdRfYnCYpdSLOwdTPTawRLSfuYbQVqMOKAEMIvfYwJHeAHiljDeqfkeKpkNDYHLeOIiAWoLAKHlQRaRhTcjNIKirPaEoMhytsCPgVwnRarUKgJNlykHuTynMYLLZVNlnuNEBmlpwjNuOVqYfNTvIltwtiSdfIDoiOWFUKDPjApIrbMIBQvwKrrAjnMvSbTmqylQgcEEEmMEKULZhwcsnRjKxygERRmJDLRodQSixepXnFGnKUPJMZqWnEufKcgqPUyVwGioDntlWiWJloKaPPXsbWUnGEUwDhlAxaORnNyqbdQbSCrTCfaMalFtpahNLlJFxntvFBpbEwWyncYRMfPDNPCmaNHvGlkAfNaNjoHclpSeDVrQVZTuuSdUjRiYoRGjaPpEbauHjHWxLLlcdfiJpVEVqedYNZkHKJZttnmNgpBauuyFcpQUCDhwDgOMxIDGpQZfmQUedvSSKyeEyWRotDGeqtVwgWKTtFYMyUKpRcRQSuSiruTuMVrLhYWdJwvDxtXWUbObEOWkJSbNNTvTcaSQAPTmFMsyopAuqtLCYrTWAMZvSjKbmJxJTRIMuPhmfKZQhGmvuODiWHEIEKGsQFQBkTpAduXSWKrToasuNlwobqRwUoXxHkFhYUtBHoGwRcLVSHxaCTRlATykVSIYPkluJVNswBQcaLxCMhXqDwcjZKiJoEfGlMFBUDXpSvcFndMgoVjcNApbbDscJYqPJQEyerdKoFNoQIKhtQbailrtQQXtoeXtClCtZlKfxKBHRxKGcsyxsywFZXwjDopCXoMKcwHTaiMTMFKXAFeheXkynZNEPjESeBYywtaZjXoAjAAMCmWwqlbbQuZWHogPLwBhpsDHciefPplYvokdOIahPGPjTMBPojGeriVaYrIoYGxoQnGHmOISTaBWxPSxUHhrfJCKfSAMFCKmhwtkmjNAnGsejrlTylPquXDDaiXOhjXtiLuEsLqaViZWmSaHNQymRrCxDGurJputUkYvGIsyfrMKWUATasQsaeqOlQQRxPnCNwRAofFiKvuycWobTnIHatsAIwZCvOmWqREMSfCFGuvQsFqNYktlZnYnQpnVKYiQSaKdQAAKVdGPeOoUIedcfDplFPpDUvvyJaHOEEWbJTFdcAqdlvIYPrIVqmVPlNNeMrIDjJWymTVUbNdfXDtQEHslBLWEXCogCdPYilCvYQkLVAnvoswiuLUjbHNmBPkhdsoJJgmjwJYdHLivPVaMGDprHqeDRTeqkfjiYPDjOTohqPexWRCaXQlBQEOFBMbKyOKtBAGREGkLNRmVQhsPbkllNdkRqpLCflxJcYPImlMuCZomFahSLITnVuIOUbZelBoXyEVoyTrMFESrQhhUsZEKkBVYfdrolImOkCjVxbYlnhrYCtBRmgNUmdSRXVZPIgHrvSpTbMikOWcCQysRGpitIPkYxPFaAYSyrVjWDKOgyoLFaYNCGAwGvaEZmLmtsmwwIgofLLqUesTiQTniHcyATQodwruFDqvAMqaPSMyCFkjAqocBtSMMqQyGpZMVmkdomclTNXexiqWQlhtvIiqJodVPrawhfwvPsikAVlIlIJnpubWGWVVgKMJqaZfmVfaUUFlXeAvMZXmLIAHpiccxuTqUWXKShakBVEZSPwAXdKYyFTWunhBPcyswHQtiBRptfWiGjKfgLCTTJcgbNjlwoZXAhswlHeufIBNwTFmWmtltPKTgDhIKbgITQGmIKTnMdhZCNhtAfNsAyikJOLVykNsRXritLIKVjBnMQZlfhmEyQeqvOBuWsCfRUcYYXdMGLWGruGMhkdybBJkoYIpLvHBENnsDBYQyQINKxABShYIFXxmpyWtQIGkFBIwmlPpBysRuwtdqaHcMlmEbnRbqIUpexDvRDYSCdcPJjNFEeGfZRymEhLmNDtpDIfYkQGojeIVcpQYtWhXZeBDtSCwjosiCnRnUaklrGNcmAIWpQZSNwjRFyYekUXOXDyUWKJaaqAABrNWiFcuDmHWgCiiXleCujostxbmeqkbkJBYvReMxtvglxQjJyWNURMWByXEmYxcrUYGOcTRrIACLKnLYvKhLVCTFRSMwFAw`
  * Evidence: `Connection: close`
  * Other Info: `Potential Buffer Overflow. The script closed the connection and threw a 500 Internal Server Error.`
* URL: http://host.docker.internal:8080/admin/users/1/edit
  * Node Name: `http://host.docker.internal:8080/admin/users/1/edit ()(fullName,password,role,username)`
  * Method: `POST`
  * Parameter: `fullName`
  * Attack: `QkfaSTqXlXLcpWGvAGdNddoYZEHGlWAggEQUaLKUuCtpVZtNYglKYFHvBBLBqwLdaPgBSuWkeEpOLSamgqvhOCvqXcRsHfhUAPScCASVGumnKaxakWFhCkmPLjGaBICHVrqyaEnlVxuvJgqvaSUmSmCJQPZUeCkRwIwggiKSiQOwhaxCoEsbHfcBeImgqSpgELOIJFjIahcNmxmJwmvYmKxsdkGwTwtSKsJNrwLqklTuuPcQEDcMHQEDQieOxLkNDlbFhQcprjYfdOpDIalJEohxTcBFnFpwWXlpULjGrutqAFwoQJHTAgTKKOmkvInjdYSAURgDoPjgpnVvGuZlemnfoafacWagKpKvggblCojkvikIpSvkfrLtGBlEAKiKEZadtJFhIXtJWxaEontroQQLpYfHHxcTQTBAVHMixrxsdbdYxldyBslJteeMLnBfnNxVsiyFvgrQbdPCaybBoIMGFIfSeSdHTWDAbEdpLhZgclMGJlIUNAwOkueQnUYmkChLKusQdKHGNUDpBOOZYFYDWPlIVupFABoJrhlWciYUtDIdocojFEWscjRBmhdyJJoGlTkpKUkbwnWofmneBlgRoqpNfEIqDsakwjKPkpYlORmpHockHfUpwajkrcWTTLqmRuOUCmhyOyKLZcyLqiujQTEWJsURQYdbNMCAFyETGhpNlLnxhKKdSYluvMqFSWXpLDWnXTuXDoWHSiPXvZNMxuRdfDLKumanoiyWfSvWZoPCudCjiDQlTDEmodadKSxZdfBWKiyfUdfpiWcDtGJjRKSnyBFeYKkHogQlJoDlhVHeYITTXxMLTnnPSHSmAoUAFdXAeaVXjlXGSQMSNLMtoIujLIShlEEMouorJACPDuXqRkbOsUJCVAphrMxKUaQhYxYKfMhOijOpWouiMEBNGmGvTrFyiYgAlGLovVOTGtMvZxeyXRXaEowvbhKQsQRsHfukeFCkOYNHvKwcpXhlNjhoOeuvrDqIHFNWVyOhKIUTqUIubapSCffpLWnTGZmrnjWvXMmjEVqcCqbqZgIpuiahOSIYngsLCmxtuTpXwGNxCMEcjVeoLwqptDTtDVlrxAZKvRKxvUwOEiBipWCdWXZSkmIiwxTXFIMZlBEyqhWKNOxiFJxnvHoLexCYMjfHXoURkLBFyiAkpSfQdkeIcPtQRIOjLArmeUGBLUmENEuNQIxbnSyEYvSMolprlaRdcOToRWDQdgrkjbUPkDQTWhfBHmAvcRVugtJilIiUkSHBCirfcMiBJWFJYDMBakreCrAhWGtfDEWKYNHrMxExRViEHIpDIddKYaEmMOMjdHYwYJqLcFxGZeuCBqaExhPJJnLdKfHAlRJATdsUkKCQkkIdEfYRwOaHZygXbiiFQlJaiKPupANcrNcOkAxLjScbwQtETNntDqDZcoxJXoMjqoqLHQOYCHStkGCKNGKdgiQZvSadkKOyNgkLuapXvLubdDfBQQATQgiYrEeHRZvSKfkpERWsgkCfaZaZAVqXljayFemhKxbTPxDKaQpyuDXgPExYiwIPyTyGeCGbLWJEJRyvocXIvMRJrmvDsadrKabVxdOnsRTUYusuGXnkNXpWmqbaSapsKYiPjIwpQaoBrTfjfudJoZaGJsyQbqKsBRIlKYLxeZbinjCaHDJBvBVoGBBZNsxnrAfDPiYRYfGvcIawsQTIDolVZMfAJUqqwbuFPvuNNZnaBDYxDGBmNDWORUbehSsulSkOFcTmyIQZkfkCxCScLOpLWoPgpFiprAENcjHTbkMfSnTHjeCSOlhtFgiIKPosVhvJZtGGQPWleqAckeEkRJfTvRYnPVfRBociOKLDTinJQreOAyEIKRdHMJCnoyrDopeAKiPriVBfHmXIBHuCEYZiscTMTEPgYuApMoZhsBfKSBAyqtleVYAZEjnlqNgRmdhdgwSKmYQkwnwMlvorBXmtKYtAnJbNHqYJwQeNDIRENYSHfTVliCLFVgaNcabVivQaDlVuCQBIscBpTYpdMnaoNghhspIkTwAJJZKJTSVGMiTuACoLHvlvgDLTIPXQZaLbNTKgOnuaDMfgmBVfmBFrqnksVZUYvOgfVWQt`
  * Evidence: `Connection: close`
  * Other Info: `Potential Buffer Overflow. The script closed the connection and threw a 500 Internal Server Error.`
* URL: http://host.docker.internal:8080/admin/users/1/edit
  * Node Name: `http://host.docker.internal:8080/admin/users/1/edit ()(fullName,password,role,username)`
  * Method: `POST`
  * Parameter: `role`
  * Attack: `oBlhkMVQYBCndPBlXkrhQxjPKvQuTYZNSVndiEPCKRLThYSxduuEmqMVOYdMwTZsOyILulRhLHFjfflsATDahSJjVdukRqHNwdDdoiWXUmiTAbEutPPrGMMJHhkhWrUGgaQxjKijEMJZqTWVevPQVGuMOqXvjjbjEvqylsYSVTCecclmlBbNYxSYteapPJIeZyybuKPIRdXTEJJoNtTljKreWAUXopqPGqlorIXmGhQoPAkdTYSWnpmkNyOZItvgEfMcHgwdeddeAVbyCUMYJRTCKfXDgemjJIYBalVIxoXaunNhNZvCXSAtStTdDbfmkFrBvCfClscgbVJJHpFGhTQFWZOQubEEMuoLgbeCjAotdhlJNGVytuedbOvJOqVGuCFtjaUOQCBvQNjfTUTwWRxxdhXZArqrqwofKpxaIFSjGSowCYrbqgAWHPnAMEqOZlyZOLiuARQHdfBcXIuVSphSuKYUBTiOplkRFHcNPgfwbsqTTlTYhQDEcKDxotNWhdFmgUVqAcGEnffuwGFlsavCooXOdfpQvDHkweVhUmqlOBOjOtowAOtDAYpQpArksljSuOtsQNRcWSUjwDofJEChYRvLNXJTfpiVurwbBUjIsUYVYweTSkqAEBPKygoVdPuMmgrZIAqygwkmkoHWxDrEiLHaAexiYvxcRQRcOYNmErnZDLyFMCZjtWTdwVJHuZpilGnfnchJvZQYjqJkudNqIktDdeMOYtEFnwEBXiiEOxMaedxWDTuclRbWGGNAHZQnDQpuSYAIfZhwWprBoIddBaAGVgnZEbbIbpJLfIDmhtrqidQrrYNjDUBefyGWgvrsIJwgyTWcVgIhioUnniQbwOakvDPtqSEIPLEbUeNClXQNxeKGnyAeKFFhCZYIagCFvaURGKJKUvwtIwugxIkINnlUDhrNRhXCUSvsKNSiLRmSxFLyVwFcIiNkqEkbsfUcHqmgpiMHJZYtpYPJDxLGnhVvbecbjePHOwygtiJwndaPEHiVoLTmHvcrwrIThcVLwTSClBnPSmWyjEmjDFQqCTiAdOgjUpfuQZMekkLADLJGjpBXOFyURltBRASTtTtwkoqwTEGBYGDxHLUQhQouxPmObJduYsllpLVerarVXFGmiuHYpYAXOiTVPsvUeCKHKDYVARPaRrMbmwJeRKUStZjVmXbVnHTAZleKhMiDKYtEexxdcBRItBAYePhAYyiiRtSAuZkbvjDdSAGubeaNOAZMHfXpEgMrMSmbWAHtNVZNBJwtqhBXFstoHxVslBApVAfYhvZHeUedAYEBGoVDQxBpWmtUZBeYKaPKsOFGbTUmddPPkdIdQaALxrbwVqPjhAPsbgNvAyjFqiDFgBsovCBxfHyAGiKrMKLKnlDVberIOeqCPaENngOvDdpsjwMRuutUdGvrrpsyvHJPhEyaXCPHQoNjwbIslaUloAsAtwgkUxvtDowxhwxOiQpQkjgEZkfFgSnAaHxCYpYxVDgysXFfWwRvpHJvBarQOKNucQhwykoQQFCLuvpuTyvldtcmVkNsmkIdBITArolXqVJRxDrEbTVqUNhURCaBgDUdVAgCHrtnjimVXotNxEHcuKHrcMxpJTQADBwNumIaNuSIasymavuJttqZyAmscraahFoFLUcppUpiuaFqYaWMKiNhBLMqZVblMpHGMmRaDMgFOQhviPbOliuYvMCfRrsjKJPPdiQIHgGXQZIoVqSWYiDZmAeWCRVcBulqbMZKlSrhJovOxAQalnKXZXTkmCTgnhMFNBtAcwkxcTPBqKDNpkhTqTqHVwXSICfULSlLPfYqnaWHIKagehtPqKEXqiwifMeFtkJEaHJuFDwsmWcObnhhBkUoTCWQeJNJooMVswKDOYbKFhJsGFdJAVMpIVwTuuaSGFPoIwYDHpSRJDXcOHMilHRAuoBCWWBEkFsOysqtqGENChNpQIllZkBlNonAJrLusMjLCLDSVFPkoBCEuUKfeQMNIbpPynFRfXentBneXaHvcrpLKWhDImwISLvsKCjLoDmoQhHMTvBHwgHPqmbEHrosMTXPhrcUjqKvrjgeNAfxJtNGFvLTHMwThRGIJNvcgTWK`
  * Evidence: `Connection: close`
  * Other Info: `Potential Buffer Overflow. The script closed the connection and threw a 500 Internal Server Error.`
* URL: http://host.docker.internal:8080/admin/users/1/edit
  * Node Name: `http://host.docker.internal:8080/admin/users/1/edit ()(fullName,password,role,username)`
  * Method: `POST`
  * Parameter: `username`
  * Attack: `arnPplcUMHFVXkkrRWKOvnEnQxSAeTPVVOSCGHUtlCdpCHdZHPQDsoWrquQCmQWSYVmFeXQMbLbkborDFefXGFJGwLQfwdIALqtDKDgoEMKOGrTfJlCqkcpjyYcVElWafhVQOdeqUrwiwrXOitvOeHgNglyxgfMSWyxKNAkuhstyqXLvpqyFqOiXoZuSMcmocJYhkPUGwrpaBiMlRMaikCjlGrqurVYlFbSFhGvUOxQDaEVYdlmDXfgpmmnPbogAVpoOcysbwMtwQocRFwFWpGBrGfAYqevLuhQWawQkYTvdQJckkUXarIjYKjlXCWqTOoAeUSWSrlELbPkMtXItuXXiGqRVcwaftfkwToxguXsVDYsprZUJvEDsxVfZoXbdbIbjOoLjLXlCGnyVwAbqdGHIoFYyiblUqtDeeiyjbttKvfNkDvhEpJobkpVcFTiKUIwtTxIGBnVHaOambnvarNkLYZSSwTqbuTvyfFdiPnoVYiohVKGCQtfLgHxvGCQvmQwWbGoXKLFfCZnaxwcNRqijUTNvaolcEIWgJlCwSeygpGksDyTpjQXRExFkpnRGqkAATNEDHYDQEgpnNdLZfxVjuHEdmFDyQuYJeypOwRqGGBIdRfnsRAHYBJFxNobGiNNehAcbwNVFEiptWlaQPaPNQiDahMontoHJUpdKIjRbGvnDlahgEmxorlcAGRilvnxgvjqFyyOMJRefgbNcdbGVogMlaywEPpbbfpgcLSBmOyxDNPVtueeWyRYQylMxIDnaHIDJySPQdOBIPpBeNKZbxpeylMVuiSylMlKuKSPygQkyXDagcdlGejbtnSEDvCbKqPFGJEMwgbpmitvCVWrRIfIixvUoEmCHsStijTdRqYyuRyxJRxItVWBCBjOxrfxWCcMAfUMmGSjswvZtEaRCQreOiyUMCencmWXrTaYbtMGeGtjTJqakiiMLabxwxiHdkyOLnwSPvQwDuvxgIePnsVSVXLaIrmKDPCpCQTGZLFAfsdltmemNfKDkwhPdkrvRLMdYsYOdLTdmBchArskNHGEscADlFeirggNoXhVBkqlhAlOSUejKamggZINCWSwAVksdBbAORSQvJiQycoebOYFRGVIvmbZSZPTCUtggWDmGwnJUsLKfCLwjgOuxrRUQaQWNYkOQnQxOiYSAnSGrsefaTIdFWoIRICBnylTiDQovCGoebVElKkmUQuTPNDfsTEtuJkTXMBlvaKGrlSXRSPActINhkTmHaSGhVpfiWCXGwSnssJiwsugFVFiCZIOuktJfdxKQloaqMyZXVvoJluhsXKmNqnowwAqOyOFSAHDbxtxQWJbYnBVhUGBafrCweAXhCMlfDxUeYHhhtsXKagNBUYjxaygPomTZQOdDivHUnwsQRsLLtuJeWPcmgjRvdpABakjwFwvdgaviyQtpbDrCiHusNiJUAhbhieBaTlbYdIJppAGnUJmPxeTpuUWVyiYMNZoSKDwYYZBHWuteMhjGvjJUnajQloTKtWLRrFQQdTSlknQSjSrLouRIjbtMZgpxqFiHRLUcmIuMiAmfxMsbqAWnPrpViksnidrtuCDwWFsBuseliFnfAyBhaBFBsDlDuRVItFLbCIWqdskbsHFagpdPIoKWBaMCVPQhDcZMomRCorpNBElCjKMHLFGlInAnYgyLjILnRDPObZGrpfLmplvdDKReISEJeOmfCOZCXRmweoEULUvldqGlbgpjAmkRVQhhGfDstCNIJQnjrFyKUoICDpbkKPeQvCbvCVMshBvfIZfIVpBbddjWmSyqbdEPfewDDgFgRMAPnWpvGKbnPnSWUyWxWwOjZEafUeGPWMcYhMeGAPEnqeETkUUTplnCcxOrivpGdHUSbfYhiRJUDWsPFhmySEpotOKDBVRcfbJXoIxEUndWtJIWncqcrTJYQkvyRasYSFBvVkSHQGpqGLiRcbcCyJjPYGwqBZoNXIyyYsaAdPjHdURaCIRCtXcZDyYpAsnfsikOTqRRpGSqLmeihowUvmnkOmQZhSPcgjKbfLmAWGvhJofXkUrMIOfBJEijuiHwdSNidFjbWHYJUlnkpPMtkHbjIvxTHLceyuUd`
  * Evidence: `Connection: close`
  * Other Info: `Potential Buffer Overflow. The script closed the connection and threw a 500 Internal Server Error.`
* URL: http://host.docker.internal:8080/admin/users/2/edit
  * Node Name: `http://host.docker.internal:8080/admin/users/2/edit ()(fullName,password,role,username)`
  * Method: `POST`
  * Parameter: `fullName`
  * Attack: `sPNHTKvbUbiAcGykILftbVXqOrZIAoiyvyDMSSoIZdLqPYQkBgNNuDlXCckJVbqhXFdllYaYdmhFsmTkOTOEOcThfPBVUcZMNBuoknJWZJQGQPGsMGkNfDCxirNhJSpPaqCJVqdbAZbZteYMjGuiijNhXntEsOxNngOpMDWRJeBBRSWtcPocKCnlpXpusucBKcWCxWiJvbumVkhEbxESCsTEwfMgdMjpFKaJTZbJZOljNcWgabwMsostqAkRYATOPDjXlnBcflFxcEHinsehgwIwfAeaGPeGvbetDJYKatXsQvCUljbkqhcSlwFvsuSgfebovWcaptXmfMeQYbbdgHBrQYDaBPCubQQOusKIkSflLNyRyppLWXiwDqPbZbsdZVNnaUpkIgPUwbiGYdwdmcTdRIKjsdAygxDwErjQZhjEcggfSVQkCpXVhgpvhTKAnHNDOONZKMOEWBmdlPIKtixtaeEPAnXXcvVcajktScFnlqKUyNDAWOWjPZJmoshuPHEIivGmpFCfVTbBMAQZQFgIlTUKNffDvIiWgfLoAeoqlXXesOsjfQXKhIZKIARgFUAeCVGnZBtnsPMFcnSQjcpUOGPeWKibgSVnRunSrxlMgeYpvFZgBWthNEqBYLHyMrJdAIoiwuoExfOSgxcWyvMdGpwbrdtNHPZKfRLJgMCOjmKQXDjUYlRpqpRWhNCiQERtinoDmXsahcwOOcUaMAhAAxkOlebiGTDEbZlRcFxxJkCTEJNuYLqBCdEBcViGCedRSrGLaZJDpeXYnZWnZRAniIiBOSTCwplJBcEFHNRKxwHOBLMeWfwOZxiTwbplavXmKXmiVKyJUFbBkaHfAevOfFRLeLgPkIwiFLNrGVXJklhpDDHNmqQfBaQryPBINMuXvWDPparDATAjyMLCOJtPwovxuVDDGgDEvpAKQnnRhdVguDwGaYQsaIFHCSiNDKAsGgUOZJULqgYhawlpyVJXifQqdjJgZXQswloiCNYoHtgKJnTSciHrEuIaGhUOYUZvNIuZBfbfUdqVYLCepZxyuqojEiHrffkrvkmUPDePFXIeIceGkdQbDNJwjEPjltgyIFfhOfXTUpYuIBUMoMNNqKBxLuOahqhhqqhPChcoEhiHQChPIefNapHxQxgBkJhNxHoUqyClqyGFsrOvYLDgRtsiNyMsKHScPmNnpCkEueDfMYaKlLyuOrTQKfNUWMieCCAAQZnFZnOOpVqAbnIBBNCDEiXayrnZtLBnLvwlrdcKKaNVKAiWoVIdqPyXcAZYHapUnFvUbZFbUeaoKhsNJreJfRimhtYUIHOAGvrWVYbsCaEZENZKDkgYjdKUidXnLdGeAYcZYhGQgjwsfUtDOEGVHEittcYBqiUtiLUuejseSElUlAodnuZLZAsBTpwoccASXfIeZWVKLsWQNlDjWReQGyablWkblxrfypnkYXTKFflRAeAsGXCMgXpqFCieghSLamNSusrqFMUGFXNCTjlHeOrGZggdjysqTRxbnANILQsornksRymKkAAZoxRmVYDkSiOoSdtutDgyUqFeWwhkuusPqiXsJIlRvBDeIHMFYjlEEopJRenakVpvNnNrqfgIpPlFBnoVkTxXUZvWrxaYpXEGJINBeXGYFCwvnsgjtqJtABavpSRfqjVvYNUlRVvWAktdNyyvMjXZWpDuBlVbeFOogBjQyJhjYxUNuBqytNpABdurVEbDyBVROnFyyaTulAVNoarDATmllkNhsGaPelSFmNBFUlgNOBUplecjGrUPbUrhjAgecythtYVBHiofXaAbjysFFceOShHRrLuAjVahOMbPNYpCdmyQiyVmAuXAboNHoMBqZsvWVyCfTGsyJVMdqHyqHRNTuXCjLHLYmfCEsKLsoRykPeGnrGAYeAwVQxATBZHJVxlWuIZabqHtemElNMQdEiaLkymhMwvjmusmIFLRxAnZtDJfSrhthAxkCFOUOOoGpAqVTlNYaNSOKEnhJgxhvqZdqQhoMRMnxmALGbRtWjqhCwUSXYtmOeRSurJiqriaLwQOHYRMIhqkfTEvgaLNpnbMBWaYcipaANZGOtuYQQEJvVsIhtJgyjBG`
  * Evidence: `Connection: close`
  * Other Info: `Potential Buffer Overflow. The script closed the connection and threw a 500 Internal Server Error.`
* URL: http://host.docker.internal:8080/admin/users/2/edit
  * Node Name: `http://host.docker.internal:8080/admin/users/2/edit ()(fullName,password,role,username)`
  * Method: `POST`
  * Parameter: `role`
  * Attack: `qHaWDgARLNRborriaWAGbACbZQnMkgRTJNftOBGcMFjaurxlBlvYVFvZYpBrrXLGERPSAoPIKyjbOoArdLoLyMNnxTNGkfYUboNgcdRmjkhoIFhudQvAuXjYLdVIKmullmClWaLTaSaKwJWGbGnKgXNSZIYXCDLSCFrZBCldYmlCJrlhEtKdDkLEJbZJXwSnWiCvgUrjCifQIcZiXCFtoAZclMZXnVyPhlgaepbccseTATZMUlBLnQervoQOmKBEOcGToYsHUQqawKPXBFcrFKspiLjMlbBJtJIoUPWFLxjTBHtseWnlNWqhBwHrGPkfRhesOMGQxtAqlQeJRhchjZvnXFjxtYeKLteGqPCrxnkwRoYGxyUCFiguCPIyMglNxjGPEytnDbvWwtxaNSikoeTSwqftcHMkeYobvXHvZlYebPjIVSYyhYKOxIIrnwccrlZyMgVLbBlHDDODZfqJpwkiVFZGLTIRrTofOfRmIMGAtOFFwqVJIBLTWiSeDVcshEFuargunfUwxxkCAOEYDJyWJtRyPOuIivxVRinJgtUHicIUxuaenjrFhgCTQPsZveIuMLVyyxInbgUfRqKdywdNYAvslxjKVwYTbEAPxrqPwkLvjtdPLVHAAbHTePMIdIfKptSbgqZcjdPdtPqADwhJKqGLtpQcvMZFXsFkBqfHQqZiNJWYfCJLhcBrunBOdXHYFxxhhavipEUJUJYnEUtZxURUdDQPuVKeixMKooJKqEtyUPtZmNIkGBEWVSRCwBiikiZslKZaxWdcQtNWDNmINcGsgcDtCZfLSvFTxdBFDlCTRcQBMnqCBKOUOGOijGOkiPBfruNwwrgNNVHhJdjOvnTTumoqBwgCGAkNogYRqourWOLrYSaJnsUWEmmxmQpOwUrnPmKYCWASTxeQdmJRrrnuAWiXuvnCjIqQqxWcipgMGHWExVJpaBbrppulNfbcnGJbbDoQOXqPPIaWJixdWUvEhcoiyWYJBOSnhghrtltkISQdHoPcTTXAbwegDXTZmfVfUCOjyGMrQORKHqBQnqJZeThMusJQBDCmpCcRVXEZaEdNCaDLyeJTxBIvlemdkXtpWZSKUnskISfQdTiqGHkSpdowvoVhqqXsJXoBCHbufFPRkdCcFpQIqPDiGVZgbOiCLwGZZFwHMJfVHxWaRSOhjoYimOthUNAoNQxGdCYugJlOTGVvtYRenFEcxWhajwatbxEKqBInHoMqKhwBplYdSjNEufleWhrsEYsyTFFHulTHGofwQLfcJAyXVVBLyLwEIgbpLMEaafUBIVyGrJqsxSGXFPQLAsQKnavBTgTuwGtRxVbZkCamMWWsLJYnKHdkaYeGxERVGLuqqHSWpoLvMmEsxZvGPlElaxtpmMGLkvwktcStMKMRuORKfAwsZytorFlSldfrSaScxVPdPgbHUYVNtxuOoKpTDgJbsTKwmODrVWdjvuFBNLOwkBRiebxDmEGrkpxNpeJwKqbnRCJkByERVdjaSqVmdFGOvovNVsFZfmpJxDEkJfiEEHLwoTAGQHnAPypMHkQwqYaSnSFccpevHfHPZlZqfIEsRdCGHTdPIGXQlCQTeNjYdfflbjotnTwhqeJtnayasknlGhPoJdFapYZfllmdbUWUACjZayeRGfQDFxcKJRTURBQbfaqXcuYdREHyOmCxWJajvDsWHABYXXGVRFhUUqnwNRJvoTMjEujoOOQyyPlIiEDMabYPHjdkDtVfHqjELbCQFNiHWXZNravFKrKneEwvZtlVhemYPXxymndkPmFqpEsBAYNdrjdQsiexlREtMpIxPxMjgXfikLthKjFFruJuqgcGbvOwVpattpauxgssdXjqWodccAFVQZyXRodrvJZjyZLhsFCGnKRvFDcFHTXoNxVSUESJdwqKCFVIkahjFCYhGXEclgtHdrkCvoChCNYmlJCOPntthTOqLFmHsMlfwbjUpahAFrxAvMYumgwDeNohpnridapuxTYASyenRWbWMIEDRkgfooaqerYYiMhxxtwUqBICAPKnAhqnQqLFrbydtSLEknPyTjadvuUKBoVdHywrPkInjqYylqqvvprvhGtjWFMY`
  * Evidence: `Connection: close`
  * Other Info: `Potential Buffer Overflow. The script closed the connection and threw a 500 Internal Server Error.`
* URL: http://host.docker.internal:8080/admin/users/2/edit
  * Node Name: `http://host.docker.internal:8080/admin/users/2/edit ()(fullName,password,role,username)`
  * Method: `POST`
  * Parameter: `username`
  * Attack: `gKLnYujCayElFngSaQCAQNxXUUmRUyMAWecorLmuJVfeOyWEjFHYYCKnOswYUmMDQYFVGKFwbBjhjdRRoQwaCvRgLFoWieWCRUUfZYsOLwVvKEMCvRoHwgQKUNtMRlxjurwNbYTyKVGMGnMoLtTdORsubPvjBESBmTryfvysxuKOdSXWYevQTndrFeSjnZDKaDRdfshVXAVvesJgZSwPpiApqoDSfiMBPjkEgWaJBsXodYqbnkXngmWYErdmVFkunKTMUIrGrBVCfdAJefnEkuDrxACkvgrLSYQflFXfmhRPcPWMrXYqTWDhFDwFQdVfyRWHOwCfTpadWlCtyvtWeXsgkPGwsNlnayvIgvHIYGVhouaNrVUDllclYiOJiujsVIiarrQvRQJIpGNjvncWGmRQrAOSEuGUdVwuDMvEaIhVcomiSPRbqtkonCwCErlSULnbDdhrKpIgYADOCKnleJRADuTnMtGyLIqcoouMiharGVWhSnZahnWrJCplgwSMuYqIkdTPPXSLDGLTLnwvxPgjPgnUpMvKMIfbkeUITIIllKQNasSmUoEcPlYGnoWVJSIUufijXJvonpEaGZeLDxEAVKiwktyiHaIpNfscocpNNWexBirqySadUIiCcKfbkFpVjyrqLWpQwGhOjrvXhgfqcZbDnhjbgqBHWaEVWhtVpmCRXrdDkiXqCDiwvcCvTFcUHevcBXQKOAtELMVUCXdHHKkjRWTXhWAQYiFacmlpAuYwbqJBUfyAUsXiaWLUctRFksvLtdkuMHrgCRsJbqmNJJZDnLAXutREcrrlKMwrrlyiVEAGtkenYugdBvAVugUvAUywCygucwaQGkcqHuHARpdDHIZUtLPgvsiARSNHNKqpdDppTxUmqRnPNMCVnWrMVvwrcLVQWRSSLdJfxdcZttpWElaiibfeGxdHLavYPgjtPHdLObMUVLDeJOcJOPYCYcFTYxDvbcQfFBPnRtMhJLlRakZMAhPDFuaTfHtZkMOybafdcOfuSqZQYRlfWEipceOeZHTcDcWYhvjFhcTcdSwwIArrPOgviFkyDQwrGRUxelZokAgVjyxXHJuYDfmFZbLdRydgvnCFSLSqwgpCOVABljLAPMsjOxFMkwipjUUXkxKnrkEhqZBjjYverjQvNfGxDfJNNOErKOGKkxQXiFMxyOaYGcFcJMdBTSNuETwqjJAyYbkqkupCBeZKfdjLSWnEJVVFWoBHqkiwrXIPoXHhlfUAuGPupHDXDZpIEVqtfOlDqfhkGuVlTsUZLFLUjCZGgQqvwfWpGVxEEyvigJtqlSkWQoYoFKEsFMudwsqMUvjYlPIUtpmqnhbJuRtjanWXuhVeLoydgZMjSxQIAkEwkRmDygLYIelhRBuVypesJlVcTkKOMTubipoPUgPqDYkqPOfNrytxvYMJDhJceiIGeQZfytWAadLWlCYqOSfIkOfWWpubWiiiYvtdHscfmVAGCmPFrnQVGxBTMqsYwqoahMUenfmEGvbLYAaCJfRubsnECHoyEhsLLHIoWwwaWDJsFOoUPtjkMfxTDFSuqLGLQhAfBMVmoVxcDkbndMetFsynSqDDNTJVSDoWImhThobcGRvqibIPcEhRFJjBoaZhvXhENsQOmZiFowFTwwtwjTSsIADUfblhFsNPLUAgMPDuvboNJmmeMdvxEHylQbqonaAXHuFypUSCcHlOVfWcJtLMPwKHhAEHpBmQSKxFpQQCWDgGmeOGWRJNVakmIOiTVixlIrbqjsNtNIicvIgbkELmCNkiGVhcEusuOMMmTvVJyAwrCXBKAkaDVrrBLJjpQXUecFqdWoauXOtGTKbfARlUIkquGnHwSMJUtCxOpOwAkgMFlOfePLwlvxwepWcwMxZuMKwbFLegHJgFPpbNqXWtThWkhxubAIVPuUPXOsMKGVEuwhCuwTDckMMOAAjBIxjCbvxBkkcrrkXLEGAjRtbveJYmuGNLOgwlomPlEWsMmlXLlsCOxVfQZxuiaNKjiKlLVJUffxbWjHNvuNjUnQIjGHdYjYmuPStWgDtLJIhxaMEyieubbyYOcJRhMPKyZoKDCyBbxnIxVCvTmmnbspWY`
  * Evidence: `Connection: close`
  * Other Info: `Potential Buffer Overflow. The script closed the connection and threw a 500 Internal Server Error.`
* URL: http://host.docker.internal:8080/admin/users/3/edit
  * Node Name: `http://host.docker.internal:8080/admin/users/3/edit ()(fullName,password,role,username)`
  * Method: `POST`
  * Parameter: `fullName`
  * Attack: `iEBXnBDIxXyNCVDhHZZgjKYFrrIwkNlMLHKjhuFSRAnvAXSwfLXnsUMmFCvFtXOIVPtSNBTVMoypjEGhAUMiqQThYWhjBAXCTxuhCmothhhAuItNAvvyAiWTuwvdcPjSqQKHjNeANUWwJiJTqCkgaKCIXPSuPOLMHMxdsvnaXxFqcyVdWGChdFrVrhqJnddOEgcfAiBMLkZCMyoGMIieHvabFTrvavhBeMohQgqKhyLMAjmRWnWuVbuNlahKKikJPHjmXWDNjWqXkVoaaQfxwlXeKkFfghtBOXvWtTxUDFyBwLBXYVqrcosmphnCxBdJdCJrXGPUZfZxRCCKyQJLGOrOhUnqjTZQkXEaktyxlsljnJLvDSgiXhyDQiCCuZkkwBOLZuWdpaVHuhaUZthWaQDAJDcXmWjbxLRsyWxowsLPeMDcJjpudMYbjFLjJyaTEtfTKBKJGTWRUMjkpEUqnLWvSkvxknJPjkieXERSchVbyHlcBiefyOMPIsJsYXXxddAokWOZjWQwyavhTvywhqwClrYwFcuChHmpchNWxRcoJNSFtnPIpfZvLwGFyoDWpABQrumvOrwSFCwSLPFQhmpdkJCjiSxbEixOiABiROpvCcuKvRLCxrHuhacAWXwdlIfRsdtcglyydjepKevGxfdIjrSPVhKMVUntgeOQEipvmiGMtYocwseTyaGfGKcQQSfwrlVXYVRMpahDhlqWmUdunvOaOitjkihqqRDIfJNfrTtmyrXntEYnffZXYaKiaQDQpxRpneNtSyiSloCpTaBEYsQuIZjrsZUvYBrnJlECsmdlgBqkGuogDPpYmufOBHpvNJiiFlgMtTkZDDMVtyyxIqORvawjQnbxfnKkMykUoaGjhONclENkdLxpniAPWDciBMoqAKcynIkJUKoGTHUyLMgAHvpMODBVGNnKMMOXYEMjOptIpAOkKnwTrTyRJtSvaiJAKDrskoxOmqYcRSFfGdvbeCTqePSPKVUnkMddcJXxDiOjIEUbqTBdyipqXtbxoeoGKLNPvBmKNyqMGYJwHMOilrsBusEbLBEOJVoNjeQDAMVpFQgcbEiEiLaVStiEOZxbBDBGFJYNCGnZVDpCFyCCsUHOmwTmsdYZOMVIVvlVleoeHxpNXHwrtywVEfKljMoKPnpdRyjquPAyIecGTtZeeXFSYRAbvmiSgROdXIWEFRJkvykKGlmRyeScyMGGCkfDfUxvscSmbiiBcEnGGvhADOOYgmkqKiSBaMQptIKqBNwOtmamZVFJGDwYsMRHSkbTQPofNcPTeqsqCNPQMiseeHYGXqLuKZOFUYVSOHeVqkbqkpqRgmqSbpMZGTKWTjbegYkGQOAKCWkbwkNleBIHbgthlEbJbtemekWwftHwVKEiDscqXLQHPCyowJgQErxYTJMVxQRtVHMdZWEmyCEHrdLTDVuaHYXPVMyGCbBKuxEQhANvpeSKPWHHWbiGTusRXSylMNvBICSChQxSUQbSBSBApKmqhPJqjlWmflXxXDXcEyEZPkbKPnHKjxlgbTRrnntCKUgnOFYtOkQgFbRYqLPvFuNhQgsmXbLlNlTNtkJkWGgqqiVlKcPkWYSllLecNBQntEIYoqFbImGUPKAdMKVEBBoSkYVGocnErYfIKDKDBhSURZIRvfrUxJaPjZIJUCxflbEFstTVhnFDuKeYWYPodPlurALYPoEFHIfXvpRTpaSbyrpUdEkRhCnsiNliICQMIOlqKQtLYuEWAyHDbThrEbIXBlPDDlJcfuihfUklFgyXproiPGJyhSgPwidkyLlMEpLXgaRxnAFIGYStNFNnebYCoyxJRHTJsyjXlSlDpiGJtWcoUluBsXofkZZRkcEUShBMLDhaTqYwBhUWwXNxKqwOXTjYMIUMQLqRjFeJEACAmdoAqWTWyXgXFfTiKCduKCubrQhimkBIyouDgSJRFhjDMoRZJxNEobBupYruMpebhonDBhdSjNdAZPpbnYQcvPlOxaIJBWXXvvCewYelCyvlPMQwOFkFbpIpEJFGQNVcsiqgQJArvjfotEwIyxmGegEfwESdESRfDTOlDfsNGNGuXwbDpAmXonBCBIRu`
  * Evidence: `Connection: close`
  * Other Info: `Potential Buffer Overflow. The script closed the connection and threw a 500 Internal Server Error.`
* URL: http://host.docker.internal:8080/admin/users/3/edit
  * Node Name: `http://host.docker.internal:8080/admin/users/3/edit ()(fullName,password,role,username)`
  * Method: `POST`
  * Parameter: `role`
  * Attack: `syyKfmDAPtVVSrPtiGlyYPnuErEmTPDNtyOBTnmWIBLubJxXwGyPtMuZJxoEbxmrknDbpCIsiraeTwAPNGIQSdPUCENgNwuNNUnNDSQfUjYLKCnxnsUmJwTVPWnVBaSSySLSitatfgXDRLkMCobOIXaNjNsYbMNCHleiPNKewoCyIhlVOyCqyQDRmxWNhdOpsotLtrMSytOgthpTTEaPULYgCfBIebohoBPJBHYrGoJTiSSxfsMcQMWOeDBykeUVSQKnbxjJvbrDYYsfhqPRkAaOStFdHYxoexdWVTMNvsVADTsNiKeYJrsuUJlDsYKsjDfMqpyAyFYuHGNEjiPktcTyOmlriuoyZbnyBGgyGldjlkCwqxpghMTHwnmlUJymqlGHKwoNZffZSGQawMrHfHYnVLMDdvjGBrBEhmEcPQiQImhMgAKJdhWlxtXZCkMXCCynnVeKeQNbHKGDOpcJbnAIpHdPUKvsLVajDhdMMSaLexoTWECwuoTdflXoMNJNCxnMnGcHyAufUxoMBaxVapXFZCQBgrIclAbdUvRyRMGWaYfdZGTDCBREDKYErgrBoqLqulWnPKcQYHvfJIpvVnNnBsDbOgxJJQsXXrTnnuLNdvSOiqHynSRHltAOhMUBcjDJJeZBguJxEwOUSjCexbiVHeMGQwGgkOIPbkSXIvJyZVjxEkXpYsmPoPFWkCniATJRMExQVaKElVnclUlTDoGjwVanfRrKYjXsQEAWmUTaPDIuSBjyWsjPiIMPyfqeWojUDbOvYvpoaJQZUkyQTQCNngRfTiwvZVauuhAFyxtLpUcnLwibCTfONBhVcKTSyyWmtbjgDpOqwhDEeGMEreQXnDwiCSvFCpVYoGflHxZIdOWfnlmrtIcONkjjbprmWsLyVkKXMcZafCdyWMYjEfGQRkvPSGwghRBfnmiSivpZLoODdMiQmcXsNWMsuHdtIocPKGXBlnEcDFBPadxrgMByxsnsnbauDixYLPkSOWhTPiCLdpTTdUiEsqQDdIsFcqMijKKkrFmkElceAaESQVVdRVofIlnnDXqfeEimoCeUtjMSWLCFmujuxIaeIYOxelZUusJEPNCqxpBQBFZmHpBIIpcfCfstknFMUgiqKokVPOjpLfQhvrVbLHJcyCXEOrNNSZBJgaxxrADgGfXslsaBgPKPxIMEmSuxpOWQIBHXXQQAFQMApQeVbSpVOSsJjcnNBtOeFcJyJUTxcfvMcOFoIdSpuJSMcPsZuFVwlZEJUtkQCJFVbfrhbGtWTVSyQWQlaZcbxTSJfHbTeTsPbGLMKuOXTctvvMyeoiAPrmNYxBpvPSIoNGGwFIRPupFNSuKsodcuXRvMwMMmTkSqdNRFHlSMFXjHWnMAjlVUEWiITJADGEojVnAfwQKlWjyPAwqZMwrAjpEkxNCQlbTRBrECrVUUbljVZieOkfYyHrEViHChxeAtypxfhemdOtdlurnwWpVKBPpdcPQqKNFmrVJDZSOrswqaYgQbDMWRIrHLyTiBVQxTbpiuxShItnGNbvQnGIsDILOJTpEQZQtYQKqMIrIkvkqsKJsPtaghQmSUAlxHCVCkXdQwkYOnLbaVgQjYGqbOZAldWmKyifhAVqljMPAmuASJLyfvcQmjfTSbwLwCgPuPADFUmmddvKjQTnAXycvUirPvnHKLYWdXSxQAYpTumIrBeLyWBejHlOWuhTtMcqjBrekwuDYwxQqgmjRUdxKKGIvlsYhNOhNoPdfUedxGScDBdvIKyaRswkmHSdmeSECNmfbInBjGbVBOrvDGCCYXiijqZGcDWiYYGLUYfkeOqViPatbAgZtMnPNGRhXAHApobGmKYSTENGfmtbNptvTZeHMNqEqZwWolClEsEeJNZfuDQKkadWDbqUkRZBhOxmLmepHVRsANknDAYhUqUbyUaFoJNKAwIyRVEATwTNOyWTQYMmukjWdVujUhldkNIKFTDmBAUFOmWuZyumAyqgiBfImsckyrrQCpPoGaUBrxpwMWVZYDbTcCpqlFpsPXTfvmvwBsaYmumOGxIVUmDYXwyqEtgJTsEfeVavRAakCbMLFlOJuaoxeQUmZnGiBNKdsd`
  * Evidence: `Connection: close`
  * Other Info: `Potential Buffer Overflow. The script closed the connection and threw a 500 Internal Server Error.`
* URL: http://host.docker.internal:8080/admin/users/3/edit
  * Node Name: `http://host.docker.internal:8080/admin/users/3/edit ()(fullName,password,role,username)`
  * Method: `POST`
  * Parameter: `username`
  * Attack: `VIKDIuGADgMVMFumqOpjPxDlUFtqNuIdnAbOBPAuDpObCluBDTpDjTyDVMTDOmqXyASaRnsaFkopshaOZpgyMTfHfSIBiiJAQETcIHCgqdOVGOEsLKtFNlFIXsnPanBUGFWZmfDphPwRFFmTZCpuXDLlWrlZmyHDFwQqtQdqwIXDkNkGBGOxOhhCWCCPsfSuMnoTccQZbuWpsJREWwZoNNsiBqKYIcYGPXfjdBcLpiLFChXDufixssAlKXgtapkAAjFiJQuKXiVwSKCVjyVvHtgXPEODotuZERYFGoHAlqrtugcfigcSXRxNbrKprkRgdidJdbAbOluMGqHFsHNmZDuBwmEVSsExbPnJpLAARyPAsXZTeWEdUnemHUwarHAxVvEayFDJlSfLfVBFViUylDPdOJbrnHRGGRPgHJtXcLZEZNGDFWbvTNYPObtQkZIXufORgauRHyQwewmDnqlKURfvyGTDmHQFAXBfjnMealMUOyFcDIwiOiKnkwiVZopjeoiqhIKNSLbGRokypQEYIKVKhkgKalukslLKSJJqNLwmYsKVRUylorolSYtPjpAxVUWnPjQaWAtDGUfOFOWWUPVQPlWblLZlmAAlaPQnVjcCghnwuJeyYXuFoMwAibGrwQWOVcRUwPAlUFHSQIFZwfQjckbaUUdjfVKaGEuvwTMFLkWyePJpXvokPpefMIvfPERaZmbDKckOhBHdTbsyctXeynDPKWvFmwLmFechoMMGanCERwkdaFjyJvNNRQPygMyticFLTLZksnarjdXnjFrOblNwrrvZVpBKegDFYGHycmuHHPaGgcnruQrEHrdkOXudXucWbYqUxTcyHoyoHkJhITiEsyQJBrnUhsSQreYNNRccBaYvfIqFDOZCGdcauFsjXudVMIuKssIwfRRRuHbsPdooNwYkxrFMhaQOZMjPSPLvVKIaYbtVvrNBVpygARoLVISDjyFPaAjEPOnfYieOKKDSULgBcndfyJCHGeApwlQAYvBPPkDjNWWOYqiPvqXIYPLbIrNGdEvAdLtUpujnXwySZnZdZZJbAnZZHkfuyifkZmiFqRumGjsfxMDKmUWjOlgcfDgleqdTbTBqgHWYXbItjFeYMtjFMONonJqyhrJZXFdSEVYNUhwdMxvGUQGYvbdBabcTuCmeWULBMnHVntQtlpCbjvVfAHcPBUmmpgnrMWtEjyLyKciLRpOfujfBjCMbreXlJmCFKsygdBIowcTbqGZwnGIqsbbUbhDvIKGuFouaeuDAugnwMCruGEbVSGjOrvGfJcMEIMVjABZAVpwhHhyCiVrFVUurqbWLqfrTXuYNhFZXlnNQAFNLflOwPMfITKlmhSRqfVVWXnUDDEqRUlePhxsHKgeieJWNkDTAtHfNmGYJPArwhdQlZOhuQkOLdOdmFXEcwBjjDhNoyUupQednMkMqmVcaeoZkhBdvdNFXvEUEmQtluWFVHRFwAKGJMnakWOpwdHnRNLnxCgRpwbIQIBKxxLvZScIrjfRhCgdpeJnVcWHPZJatZvveGcIHyGkquZXjJWlxIHrRKZqUuVsGQoxNtCHoNGrfVgYxTnedHuvoCWdaFRLSmUwxvnMnNqowkPBPSEFcQphlwSOZISgFpUsgwmTVaXurCxOMxVkBQgnGEVaXhtusmwGXLTLXnxUwJXgtqckiqJDaetKiMWNUJuofyrCtIYNuOuCkKOPUTuYOYxCQltHOexyIRJfcvAyEEsvohdQjNlXodryaQBgEBFprJWjCJVlfMxbcOwviBQwRpVmfWWpgGZYjLPQpnwwYvelOTjulqirJorjaQNdWgSeUuSqeQmLCEmjdFLRwxNoSvWNugfAKUZfGMpjBikKgWaCTUSVyDIqRpIpZfEydtLqfFEmXkhRVDsxqWnItxgwjTjtXTwNAljYxqcQhHJGNCrvACStnZiFgbaKMietKPebMNtZojrgtRPieOCxqPyrJWRbMEBjPigZZQIpxFCQntbAYIEXprHQlRRpNlnWLgyasUxRHMiaUxGrIYvBTXcUAaEQKlLFPgiNMoSVhDPfchQsgyANLXqCfuEMxkOjoSKZYuVEjXXKDMSnSvbgT`
  * Evidence: `Connection: close`
  * Other Info: `Potential Buffer Overflow. The script closed the connection and threw a 500 Internal Server Error.`
* URL: http://host.docker.internal:8080/admin/users/4/edit
  * Node Name: `http://host.docker.internal:8080/admin/users/4/edit ()(fullName,password,role,username)`
  * Method: `POST`
  * Parameter: `fullName`
  * Attack: `cYluNcJHvdhhGxTQSReFIxqLloKRFvIcCKxKKwrxkohZZZRVrlRstBDFayOKcevwMmOwNqOXduweYroGaKNOjEmiBGJUfMqOGRQlunBaeNfyaHSyjwjimSlSCXwAVFtroTRUpcRWlUpOWDwlwXgcgCfKEhhQXUSNvdPuonlBnqVnfIMUpNBTopMyZOtmFkHUVUkcXUsRQiWBbNnXwtBTsmLMbONrjGDYXNAcBMgmtmhYwqbHhWPTbPqwkMLQRaENRcDIohvnjxcliPgBILorrEjmOCNgtFmyBleVipADfeUikuCfFsxoWCjJNFJbyyLKkyfklmujIxIyLbrZhBpVcgmOiThGerTxXXVOvvQjgnRpYuYLtEtEXyRuBaQmHIJhGMGGoQeiGNyEWseIFCmntZGPJdgjkulEnntyUejCTgyJIRmpuMkPCcudMEvZtvsdcLRpNOSaIynErmVJNbdcyuIWVDTRdNGksVqZopVEHwYbrdRNWDZaTwhXMgqbIxOLfkXlsATihkIdgdAEdxVxBIbKLsqowsAllGqCSSqmlTDssBhPunkFOajlAmvCOajhuBZRCciYIKlIkRlKqcoUnEYakMAgAclMyUemIKBRbvrWejGWZwpZJjKwaacDKtjUJsiMZkyJwdxZximkZavRDWyqClVxJjpCWtCWVkxlUlVdxrYLYuVTSFClvLNNMBgTOsfhMyssPJyFnpcTSRLZmMudXQggvNNOPpUBZZAZFSALJYYPkltttViHXmGqStjFRPXsKDgIolLnDCJtXEfwQvFlwABFncFPKmuZIjbhPBkJBJRkHGDsAhXKnKCmYpwVRjquOPqrHoWNhyZgKvXZfDtOtRdQXDjZfekkNwxYAcoaWjILlaIqetmCGnNxRFNZLnWuXgDfTsEdlmpBTBwnBaofxNXrXiXBbRcwgedtRniTYaVFpKqoksSSojsiYtsDZAhJsAWuSkghULsmIcjsoFBJKdpLakUQNKUvEMgQfTQknjoLuCFJNOVbDweweCbGcYilCqSKmsfegWEVMNxoHSAjuOHJfOmgjCTbFeXCVwWFnCEKYpyseiaNPAMIeLLulKOkdhfvjHOiwWLAlSkrwPhbuqEnFFbDcyFmwrFTnKsIetlNuSNlcZhdyWXlBmFnSjeeWbqpUTtrrCZgQDWnhJgiDRqIcrdfYLIYgrVFlskAHbuTOfOURBCoqfLfTbJBjbdcYxPWMUmikBFHHbvcWKXvlCBcfDYvWnchkbuypUUcHndfLAharbfEBGLBOhYbZYxfdlJKdKUwdfTfGSyYaLjgfgejmTKSVpXPpCgSEvxQmOWPEBSMpfPuaUJDxTZcJOkKHjXgaXnyCTBPitpheaGjYXSfFnWLuFSLmEIdZfnRKGHJTbcpKINLFIoNmhhnFgOwHncyErtAyIiLErtWVnZRRYSxeYlEepbUySeqnXZAAYlViWWyWHmMInuDKxyCdULZKMwmhXixkWGulDPIFDLEDqhcvgIFJPUxGwbLEeEMNCSkoQmOHWIjHAFHaCTJLGkFbamJevrOJBGtSvktaQDyJPCOFPhprUcWNtEMtVnNQdFshSvlFaqBvZwXoedkVEoKtPReheBwScNqLDcxqQfLXrKpPwWRqjhAFXjfBXHsDlvGyVrXngojGtllCbVdAEfxudXfqtDiQyXFaTJIheUeQWGkMoNteTDKaWYdRvmTmxMfUeWlOepxUTIrUoVSijtgfaIXXYKyckrkwxVkaCVVhSkFvkhVnIPmIweqlydRKCGLvERlIxppSruCmseBUnqWYZwVOahnSsAnoQumgNcsvtqGWeWfHaeQkQtPqRpclgyeEpWtJuFyVKOeaWKyMIMpYPLARMkhkAIRbgwmRFGUtSiFlqQxDHNCHiPjUIbXTTSTWBQshtoJNOmlPMZMrSFjCyJiwRWAsVSMqGVsMAAQujrYNnKyQOkgoEdlmnqmcmvuBtVRrETiSFSuuLnovYcSMRYhxDdHcCgtsUtxFHwqiWuyHjjefIelNFBUlEZOqYxxqFytScAUaMiScoKhqSRBRLneyYZkTJahNLBwpPHYJlJxOdMxCLEmZXlEEAWXqnAyLvwT`
  * Evidence: `Connection: close`
  * Other Info: `Potential Buffer Overflow. The script closed the connection and threw a 500 Internal Server Error.`
* URL: http://host.docker.internal:8080/admin/users/4/edit
  * Node Name: `http://host.docker.internal:8080/admin/users/4/edit ()(fullName,password,role,username)`
  * Method: `POST`
  * Parameter: `role`
  * Attack: `NxpKYyVfVFZKkWkpXnDaKmuxnWyKeZtIUvfZGlEahUyEmbSYnFMmSGcArThMvcjsmALyAWyGGVqxjDurEFcnMJsqhIdmxJLgadvfPIZDaVEqsWgEYDvveDyLJilRJXRyuJrqwyZATRWpRyeLRCNxDIieIfMtarVHTaRCpipPFBCLCSdrMpAUNJsYjfXrYRuPesqcLPwlmPNTJCKcrshniVSXgnaUfuXhOupOwvbxemtYURMsaYtqeZPDTywmKhibunUkUDNGdNwiRJCtoIfsnJjfhUKAhdvbsBLwbGaFlhBrLmMAYRWjlHhKuCfTSIqbLNBOfoGMJjiolVoiJLdTAftGpOFgiTQedOIdyopTXDpSfkrmOGTgFdSNmGSSPlYftJwwjygOWUMbUebeiFvvaRPFHrDlrnRPYVILvbDrYZIKPIXSGFSWhQOMmvpqkTyMdhXaIeeBTomoKCOXXMbOUIJZInBtLSOudSGQGATWdZebGAQUZseyUaatvnmwlqSNQALvrRjgWMQtJvJEJWSVgsJicTXAnCsPyRZMThuZXkuLXbUkGGAxdjZGKKPEfKYxEkBbhjKbQvWgotjlEdrLIYPpJlfTHlGVmcRJTsSDkjDRBRMvRAguEbgyClPLTlkpQNmkPlWYGdFmcJPIWTgCFVoehbJloTFgaQSmOmmiscLqcYFxMjNxbRvZpHGJSIeBOmsHfNNZVWenpekqRpLicLYdErHbtodcemyMShoWkmZkGdmjUuLHLcZaaIOYIGBEDByHywkADtxsBtEXIMZVMcdZPyUlgsvqShAugSciSpwdrEdkZqPacmgaElOTNDWEgQoIAdYoeHaMOogkNXSNifsZrwBiYeQgDMKRWqLjAoTtaOgQmWMsxvqQreAiuIPDZQJxhAnpUQQQjEuqWWXGvaOvMkQEUsiIhvNDGGtDKmCMhrjXqmZdwamIlxjtRfAaTauAQOjtEFSKixGZELKrDWaVmSyTqVJSQJMVYVTwqNMXVHIoKfbZvVxhynEpIwKZWCSrUdpYnVZlZtGcyhWNkIiHUoZNtflpOKGOxtkKKGJJjGRUFDJWWebgEOrRnMKJiOPPuvWHImJXJaQTtVlXWqrwDlAaGSkUaDWakBZaGOoWnZZJYWbCDIAtIvKdisTpJUyoRxVtmVEkxJgySxHtCanpvdxolnpQmkroKPGJgeeecKJTEbJkErJyJebJHpSicsAcJoMBZdCGpwddSymvTcrlHylDJuQdCjoverCGXmOVcnuZpwxKVWvkGrOsiQHSWTVahRskFjANYwVbqwIgjRLvwbuVOKhnwxNjQPjrowNbbsyhQvJslEpOCbmjRklbJbPFEdRsGuwtgpfsySYrpoZpYSvCnEAEZmLkTsdHdlAvqPpsmXDURXUNRcvdUUwiUDISoGyrKSOWjFahlIjoAIqcPwdeWcvJdVfuVuvlFnivqlDbGjrsSQvnOICqGrRUEkPSSetSYXNpcFujoGlYiqDwXYKZHPsysMthNGaqqFBKCQEPOBIhykLmlLxIZuBcyWFhdXfmcemEBRPHihRplaaVKXxpfshRBIbDvVDNoMvxIxqgYfUrgeYfsEojtbyxVNsdTvlbIVWsRiUVrrTwGwcGNcQUpglKeJDNIZDOPxjPHUcsdXkKAafhhnDxINSbpaFnJPQlKfVfOLAoOWmTLymANTEZqlPLRipfFIeMtTkOfwiNnheXkkiySSrUVHDfNaStUQLTLUKeqHOSmHwiKuFqjFLLJeeoZDAkXWGskFCnAnUXWviUckGwRHHMCDQcdMxCyCifOqHBbKHHxTfkHtlcGQQaJtDJUHWfRXBvCUUTGTNpjfvbVrayRUJLVegDRsmwqOiarkiBDCRwMXbQEtGtOsmDlqHcaVKdJTVqNtjLiFZAliHTXqNkIEigcEtxZbZxXSKrbuGxohQlOCLbmmMTVEKXPwkSHrKuMSXQFwZawadeSDpVxGTtvCEOlHTrjEggrIGHVvrRQcVnGyDccLLNBtWWEZiSDlbjkhHayoKnmMWqZfxyYxOCkNoEQTekQQIANSLCFkcFeawCVcJGnMqRHIspBZFiPtjZOaCJNCoAeowSLWyn`
  * Evidence: `Connection: close`
  * Other Info: `Potential Buffer Overflow. The script closed the connection and threw a 500 Internal Server Error.`
* URL: http://host.docker.internal:8080/admin/users/4/edit
  * Node Name: `http://host.docker.internal:8080/admin/users/4/edit ()(fullName,password,role,username)`
  * Method: `POST`
  * Parameter: `username`
  * Attack: `DeMwgtFVlpLhvTtCVJbodsVtrLHAQUMLsjdtEVCGFbCJXmIRKcJSXEEmpitMUrGeuNNFJZWPDwIpJJPUlrvWmoMNfSqURZkIKuYACijZpUsFmNclwelOGSFuGkuORpuxBLCmFQmLnBRuRJxNvlDTwfAoGgBdWJeJvtSMamAOHKAmjhOcUuqtdKjCJDWEhqefngQPDrroAHFJrwiFJBQBwkiXsPKunGNjNoxZjlLSZxyoAyilwPEAAyrELnAvXyHYKvdSTJZfbeTqcLQAKmWiNAGwrHdTvkpJPYiFfvbUpwWSOVSaEvLuKNlPqmpIGakdvHQirWCXbacpVXmenguCqWQucFTuiWwOVmFqrjKEYPCRnddRXgTBMaUxNjnNikIAJkKQYjDCKSXemXZHhiYZvBkFGxaCoAdWxxABmQLtKSAUtEIpHPmCjqNLQYTvpeOwWGoKFwkDdMhVAsnhLLGSKdApgImvbbBcyrUYePTdlSZGAqvfaRDTsCZDWanAVqyJFotdygxmNMnGQVusBAZbIslfkAloOTOPVjgleqWGBSRLyMjQpFVAJfHKcQoEySJRvwxZnYfqHsmxKwfcdejVeCgIEvknfquPtrStQylBZnIwoClQXGogRBeZkQDeLKMMfpDZhZNReYLidqPZUDhDWDkufuyusdUCtBUbcEnFEKNBaNooHYhUFFHLoWpBAwaedwEAokyZpVIsgTKKgNsPVkCFdMjPfoKalQrsLoTwSqYvmDmjyGoJPKvCbZuyFtSbwVmLypuEWZiwcduvPHArXVwgGBLooLUgxUqstrCpHMaYHSUGNBVQXRqWEVytIuboEbwRCTnyeVvoYEJONYghcVYTUFydEngNAsDCdxtnAVSHDNsNuPUjfNvIuRdrIWUkFFPUdiXvpeIFuBGxhOyXYuPgLgRntEjyAoiYTcGEtBymZLhieXciSBXPPkJBAcyFIxituqqNKtVJryMpwQExfWbOpeRvFqfqInUkoxRHCYNgRnlTCWPiOaiblXkWoWCoYdtaLtmCrPEDTXdbKAdkHFgYvHUqKfcZKTxYCTukWbMKXScyBiTMJnkYRlhmGjLQwSwhPcdVHrFvOHLWagHnrQEPVNFaWsgJQoAYIoxmtwBrEQTDyouETMfYEtTThXpRebYpngBNHDRYYQccjVtqrVKfbhfXuPxFsiPSpMrIcCZrxGvviJabjAFBkCLVXcpNrbftoQqxarEUdxrlnHaEexgcBysZsaNlAWdXWYrNnMCKNFajArXyQyxEiPRQlCVgNWaPlFrTFtrketXlCrrWPOHHrupcpTTGWNXMFNJGtMsEVupDKvKVlnQYXmPOcAIlkTVmgfeDiwsPAnVRFIjrIicZbwdcNkEZrhNOyhAVgTRidxTIxrKbfUCSSaDVkNkpeSfKFumpMTuEtHMfxMBsdLGHiOuFWjDhVPPHIbNGTiXQdQumSnXCcRkEAZQpitWtecPTAfEHsEZGinBGpUSfCOwdTihKURGTlSvVxexKJtPuwMtrxslMoxeDtJJKaJmEhcurChrWZAAncsjkSvIfDHqDbISrZuyiDDZOHjQpUJxOHyBrJnysQoPExNLUpOsLGMPPLYYhAAHkygrMEnjyhoqvsLwrWqgEBSUyBtAtMMPwHRwlsNrhZtrCrmxWTejfDuVIRAPUSGElTkqsdrwIcKhTbPVBxwebHpwcgQNjCUUoNkgmsdxQuuMSAQYvaqsPXYEVJrDbkrtGmdowBLnhFthdQlSPZVmanqCdlwQFDuqFjArVeSDbLSAUVoxhmVQQDyLikBhKAaaVBFdGppfQaddfttijkcaMSTOBTVhHdZSOVwSQUjaagIPxkxOJbYwtXWTYPFDRQqHRrytqBpYdeGliAfAhbwuZoxhWXHTKGWPnpLsEdEmSMMhpkbMJwSACmVDeqfbFIwhcdrsUCyReDLvGCAVGDUeVYtuDUvXxWAfZqrJddwvkprgbjfBfZiltBhDwiyxvyoawuUIcuEompmMVbiLqXtXYNWZWKnDaMuJGLKFwCqxXaFDvPcDXwMCJSYCTygaktWkkCgvsIItqPAvQYobtlCyIilItHiCqYmtJrZZtorWc`
  * Evidence: `Connection: close`
  * Other Info: `Potential Buffer Overflow. The script closed the connection and threw a 500 Internal Server Error.`
* URL: http://host.docker.internal:8080/messages
  * Node Name: `http://host.docker.internal:8080/messages ()(content,sender)`
  * Method: `POST`
  * Parameter: `content`
  * Attack: `CCIAiOvQmHnTEdslYPrqnbYVoXgXTJStlispXvRIShQOQAykbGiechkCxHhhirIiESCNjnMTCsNPlJSWoMlSPiRkoNXrfmRBydUtwMlAsGlCWHHgvGdvLxYeIFQuGYmgiNQxZEbjORgfOqhfwPgbLaiowmJZrfCehrtvcCXJwynolsyFIlkGPMaZPqZgNOoOMKfjJxwtudNyOmFCTAinJqqARdMofjoBtoToocSvLmInoGSeRikXHFHyEyZmHORMUBknSjnjsIelXJJIinhyopFcZwIcBceMmrJgKHtxZEgdGLkZeZYKkVqcoohLwtmJuoHakHAHfMgcsemTQfxgQxchegZYTojxfOvXGyUusTxiMcXqOcJHURNiMMiecfdviiVLSEgbEKARAwaEykrfvbOvomEFBmDoPqCQxNXrGCGNbTjrAOflydUEnQKKIZUZdCCNvYvjZPVigyqcEbnopiNocGSDfYfCsJatGSRHAtprWOyKANEpSgdcYLFyZmZwITVavfWieuMhUtKKiuNtEZlNPiXtKLBykPGtdDQerCspOsyrMeDOHkBsaeLOVcCtjEiFCWNVTJGrnoOSbrfwVghqIwGaQexVZoKlyjHYhJevWZJqicFdoWPDYNLyTJvDafPbvxxYfcioRSyLUOSPWsfuGJpCusVPUTGLJDoQVydFjOwNeDRMnVvpqiXMsPaDYjvXpBULvgllyLIJSTscMwBvJoWngwZeqYGlsiQcKYCaMBUHAoEchvCSJTQTdQgKmsijNgrurNJIoTbXMqVHRmrbHugqnLgptSbhbsbPhdLXOhfVQeTfuZhIDWfrYGpXkUVKMZDZRuXRdTtUtrZqqEFjOaHxTTWalbYIuqsbnDeerHVlCMOAqMKHOqcpwsgToNmXEmFxtLePlNKBrnxDeESmvrXGKrwVJVFjJZunGApGioYHrOwwODniItBXFcNQEaVqIWJPWbsEcutxJJiftTrdFKpPVLpNGcgbsDFUVFLwwTehEWQWtyRVWceHxrmpIqPWcsRbSHarFhgnpRHOPOMNeHWPyLyoKjfiEVetTiJmqDrdZSkVMBHsTINKRjvRdseVNlHKysEfNrfMlTySviJaZpLnRYxtoqoHLaSTrfrIanUvAxZqBseoNhHdoIPrSBWLgsxjpwVSnjGLBiHdZMDONRBugLqEOtmgZBsYQiasaMYfbHmXNVWTeIdrrptvqBOpIEpbOJjlQvjbELpGrkOxBnUmgIOHbIcWoQaVqlcUnLAwcEJWTLmwOJEPIPHkvooNXYHecoNOekEGVrVjkjlcTlwnLMrjKPbCOSAYWWaBeEFxZcCqfyQFMWHhbxRWsbSpmxvAUNSYQJWEsfXHLogfbJQjTOTVuknyvFIYeEveKDFpsOmMdmZnVZAFtatochCZmrDSYFfARHBbbglLQbSEBvmXUHPHZQcjratiCjHAAXyyFZpYEkCItTsbMGsXNQtMIgqQlfVgDFGuxNZStrdBgmxSVFgwEJyvYXjCJonRBikkrrQmjepGLyTljoMDsfqVZCoKhebBfqtGLVTxvFeJESuBnGbwnjpxXFSXeGItbNAUolVwZpHecBBlYXcNoaYCigvdEeIgygvTlgTUKrIlZJDLEGZKlDrTbbnDfvyTKqWCeYIJslxKfXhWSObMsfVOwbhwoBHmPhsGXRfeaLLlRRZpTKNHYshatxctEBNrydIwWnWtvenpDijFfeDvxWrZyDAyWetwHahKmIAFqZVXZRlhLNyFgsicIbGwQYQYMTJnnXllfxllwxSbXWWfiMfmtUxriuLQeeqfDZuLdZjnmKdRJhGfyDMdSxktyivgadNeJCbiBFmxjHEnfQABgdQqTeAahtLsFTjVemJLdWKhujDRgiYBWcJXJIsCCstyZjybEapynVirelTidgTRSmVxFrMvNSpbBtuRiHCrEPAMrOCusPrKaRGXetONeFSUnFyBSTgbuuGgacufPgikjKQVUaqBSNKrgQYPMHksLlDBiEnHOYifBlRZIdqYsHUjwjVFXdbVCoOFhmqcRsViTsdUeoVUhyFrOqiMEIbcsdhCUQMoDfZcsdgucwkojKONRMrsWPNP`
  * Evidence: `Connection: close`
  * Other Info: `Potential Buffer Overflow. The script closed the connection and threw a 500 Internal Server Error.`
* URL: http://host.docker.internal:8080/messages
  * Node Name: `http://host.docker.internal:8080/messages ()(content,sender)`
  * Method: `POST`
  * Parameter: `sender`
  * Attack: `wwPOpnGYBobuhAtXEUcmSxFKiamJGVuNHlyxuCvIWOINiMXXuHGOupdTrUxrsyXomKMmkxWRGaQVPOeGFUQIiicvrkEJquCROpOpxkvnOHitBDkQJvdxnUITxngIVBnCTvxKlFDfqYMBGnGMSrpaIqgGxStAdEXhoGwjNRppRREHmYArKxuHilWUshZwKKHDaONDKBgrZPYlqMAFTOfnAMyAawSZGQMwyArCPpGZkiLTXKTcyjWPXSSjvLKeOeGssECcMpwEvaGTVkArjeVLhHHiaVLGehxVibebSJharejUNSMkuGBMkiHLuywmaTQqDWYkYHTGNFeJJGHgmptllUdpIfXZfSMyysHPLhXgmrIFBlbESnfKBdItsdpJTLUslbNsycaoIdYrOHFQDVFugkOnYuidHOHHPwvmbDUkHEFHXIeweusVNRRaHqAxjdQixugfkPxDEDNqgIWUWdGMoIJWtOEgnmOGpeLDUIytrkewRMEWUYvsMwRgOXOElWlDjWeCdeReqsIYZTOZXyrHfrFYJVrOVLSgOapsVdcoalZWSpYbroMWpQvIWkinmprJHVCjTWSIJrDDvpaHuTwJWxGxGYXUvaTevUgIpFHqEpZyPitFwUaAFiHuBNtsICWtZhbTkgmIgLJrwiioEjVwUuqUWniFJlKXDsygewLJpIuRkgftLGZrZDAhQndIQdGHDVeQVROBlhsKNckBeJnJYMBsvucbkkyLYWfnVCIYdQbYCJToSsFdhXREMdjegERmULBaxWBAuqfAaeFKWODTLBdMSjfkXccxRdNaQPcdNlXAwqdiMNNNIqsmBIcJhIQtTYKYQFcwHmYWyBLrDLNCKjOkeqLFAUVjfunwRlLedcwVEHjequmytWZWGtURwkyHxwMLOOIkqUeegYXhXiNeSnOAFbUEaGyKKYAyLLlTFkCtFXUXHtvmjRdGFOPCDJdWWoqywqrKUSbndMHyABtmMiwgJgTpBmkMkWmdXLVepfRXhQjlrZJGdsYCuusYqbUQQJFgvyWqiMJxeZMdNWIlPMUocNqCTXMHFpuiPYHayTaPRokVhByWbYToJiARKoCXGVHhrpeTpLSaGccAyLcCIRhLIcOoLCtgBWbjmlHPiLAeeBBhcIaXhHMfaFpWwbGvCopJoXodoySlMpGJcrRKGNnCgTpHqCdRNRhfJSQwZasLmjhgBUUJKYyPqTsofWOCLBFSBXrmQbAVagVcAewuEpWRQVBYDaWorfbMvFAECRsSpguhBpqhKWZyrRyYCsLOQBfrUXQXuvnLgGJkfMnqbPTtnlNQavHHWrChuneLFHNJGrwyxNsPSaqCmjuDOGjGfCjKrLetSPYcaforiBmwNLCQHIknhFUtajaSbJidXPXeoRiEsIovYVudipvoxoVDvuTVhsSegnRoJbHiifvmvQCVjOCiPuyQNycgvXlTKbRYAUXJniutSMhMKnqatAkcGkwxtKGCQXuVkVFqWOuZxmgOWfnnCOaZKLhsfwRPEVQakNvakFfQuthjJfjuDoRohZbrOukmigvNRgYjMHYnmfehEOslfCmLWbPTujRMuhZCuhGxhtbNfBNxZUAJVpoAlypvAuWXyrPYeLwqjtxmXgfPwrdgasIqriRJDASNDclkkFRHmladbkYKjMsWgtGJosajpkkVYULpjcQKTBpvJNZofyXpTWeasFvYfEKKsYpJykdFuhwODaKffZERbcMGmdvfswTAryXpqUEByYSywBVhorvDveLOmiuxFceITnpdIFdQSHtcnCMGiMUovVjxJAWjjZSkFlvhIpABUFEqAtLYTchGEDpncaniWWtVBpjfhexYijrKdMiYbgstoDULcJFBXoULXLtSkFtiqMJuhiNyNRYJGxCfgBecMXecmqJMPqNkITGvRKsracNkuRpfWHOxfwPWOVniQhuATvCnayGtLKEcudDNdCDdbAAEJdbJfmvDxhmqbiNQGlprPESkpLOliOGPmMCNixIbVexqmNCnBGypJBQIpIBtjTZsdxPWkqMJXoSoYwgbihwOBjoSRYkJhyVkbdmxQKiJEOpxBZWetSWLriuAePBGggTHfDWglINapaIj`
  * Evidence: `Connection: close`
  * Other Info: `Potential Buffer Overflow. The script closed the connection and threw a 500 Internal Server Error.`


Instances: 16

### Solution

Rewrite the background program using proper return length checking. This will require a recompile of the background executable.

### Reference


* [ https://owasp.org/www-community/attacks/Buffer_overflow_attack ](https://owasp.org/www-community/attacks/Buffer_overflow_attack)


#### CWE Id: [ 120 ](https://cwe.mitre.org/data/definitions/120.html)


#### WASC Id: 7

#### Source ID: 1

### [ Content Security Policy (CSP) Header Not Set ](https://www.zaproxy.org/docs/alerts/10038/)



##### Medium (High)

### Description

Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

* URL: http://host.docker.internal:8080/admin/users/1/edit
  * Node Name: `http://host.docker.internal:8080/admin/users/1/edit`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:8080/dashboard%3Fuser=bob
  * Node Name: `http://host.docker.internal:8080/dashboard (user)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:8080/login
  * Node Name: `http://host.docker.internal:8080/login`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:8080/messages
  * Node Name: `http://host.docker.internal:8080/messages`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:8080/search%3Fq=test
  * Node Name: `http://host.docker.internal:8080/search (q)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``

Instances: Systemic


### Solution

Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP)
* [ https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
* [ https://www.w3.org/TR/CSP/ ](https://www.w3.org/TR/CSP/)
* [ https://w3c.github.io/webappsec-csp/ ](https://w3c.github.io/webappsec-csp/)
* [ https://web.dev/articles/csp ](https://web.dev/articles/csp)
* [ https://caniuse.com/#feat=contentsecuritypolicy ](https://caniuse.com/#feat=contentsecuritypolicy)
* [ https://content-security-policy.com/ ](https://content-security-policy.com/)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ Format String Error ](https://www.zaproxy.org/docs/alerts/30002/)



##### Medium (Medium)

### Description

A Format String error occurs when the submitted data of an input string is evaluated as a command by the application.

* URL: http://host.docker.internal:8080/login
  * Node Name: `http://host.docker.internal:8080/login ()(password,username)`
  * Method: `POST`
  * Parameter: `username`
  * Attack: `ZAP%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s
`
  * Evidence: ``
  * Other Info: `Potential Format String Error. The script closed the connection on a /%s.`


Instances: 1

### Solution

Rewrite the background program using proper deletion of bad character strings. This will require a recompile of the background executable.

### Reference


* [ https://owasp.org/www-community/attacks/Format_string_attack ](https://owasp.org/www-community/attacks/Format_string_attack)


#### CWE Id: [ 134 ](https://cwe.mitre.org/data/definitions/134.html)


#### WASC Id: 6

#### Source ID: 1

### [ Missing Anti-clickjacking Header ](https://www.zaproxy.org/docs/alerts/10020/)



##### Medium (Medium)

### Description

The response does not protect against 'ClickJacking' attacks. It should include either Content-Security-Policy with 'frame-ancestors' directive or X-Frame-Options.

* URL: http://host.docker.internal:8080/admin/users/1/edit
  * Node Name: `http://host.docker.internal:8080/admin/users/1/edit`
  * Method: `GET`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:8080/dashboard%3Fuser=chiefadmin
  * Node Name: `http://host.docker.internal:8080/dashboard (user)`
  * Method: `GET`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:8080/login
  * Node Name: `http://host.docker.internal:8080/login`
  * Method: `GET`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:8080/messages
  * Node Name: `http://host.docker.internal:8080/messages`
  * Method: `GET`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:8080/search%3Fq=test
  * Node Name: `http://host.docker.internal:8080/search (q)`
  * Method: `GET`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``

Instances: Systemic


### Solution

Modern Web browsers support the Content-Security-Policy and X-Frame-Options HTTP headers. Ensure one of them is set on all web pages returned by your site/app.
If you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. Alternatively consider implementing Content Security Policy's "frame-ancestors" directive.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options)


#### CWE Id: [ 1021 ](https://cwe.mitre.org/data/definitions/1021.html)


#### WASC Id: 15

#### Source ID: 3

### [ Parameter Tampering ](https://www.zaproxy.org/docs/alerts/40008/)



##### Medium (Medium)

### Description

Parameter manipulation caused an error page or Java stack trace to be displayed. This indicated lack of exception handling and potential areas for further exploit.

* URL: http://host.docker.internal:8080/currency/rate%3Fsource=
  * Node Name: `http://host.docker.internal:8080/currency/rate (source)`
  * Method: `GET`
  * Parameter: `source`
  * Attack: ``
  * Evidence: `javax.servlet.http.HttpServlet.service(HttpServlet.java:670)\r\n\tat`
  * Other Info: ``
* URL: http://host.docker.internal:8080/dashboard%3Fuser=%2500
  * Node Name: `http://host.docker.internal:8080/dashboard (user)`
  * Method: `GET`
  * Parameter: `user`
  * Attack: ` `
  * Evidence: `javax.servlet.http.HttpServlet.service(HttpServlet.java:670)\r\n\tat`
  * Other Info: ``
* URL: http://host.docker.internal:8080/statements/download%3Ffilename=
  * Node Name: `http://host.docker.internal:8080/statements/download (filename)`
  * Method: `GET`
  * Parameter: `filename`
  * Attack: ``
  * Evidence: `javax.servlet.http.HttpServlet.service(HttpServlet.java:670)\r\n\tat`
  * Other Info: ``


Instances: 3

### Solution

Identify the cause of the error and fix it. Do not trust client side input and enforce a tight check in the server side. Besides, catch the exception properly. Use a generic 500 error page for internal server error.

### Reference



#### CWE Id: [ 472 ](https://cwe.mitre.org/data/definitions/472.html)


#### WASC Id: 20

#### Source ID: 1

### [ Authentication Request Identified ](https://www.zaproxy.org/docs/alerts/10111/)



##### Informational (High)

### Description

The given request has been identified as an authentication request. The 'Other Info' field contains a set of key=value lines which identify any relevant fields. If the request is in a context which has an Authentication Method set to "Auto-Detect" then this rule will change the authentication to match the request identified.

* URL: http://host.docker.internal:8080/admin/users/1/edit
  * Node Name: `http://host.docker.internal:8080/admin/users/1/edit ()(fullName,password,role,username)`
  * Method: `POST`
  * Parameter: `username`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=username
userValue=alice
passwordParam=password
referer=http://host.docker.internal:8080/admin/users/1/edit`
* URL: http://host.docker.internal:8080/admin/users/2/edit
  * Node Name: `http://host.docker.internal:8080/admin/users/2/edit ()(fullName,password,role,username)`
  * Method: `POST`
  * Parameter: `username`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=username
userValue=bob
passwordParam=password
referer=http://host.docker.internal:8080/admin/users/2/edit`
* URL: http://host.docker.internal:8080/admin/users/3/edit
  * Node Name: `http://host.docker.internal:8080/admin/users/3/edit ()(fullName,password,role,username)`
  * Method: `POST`
  * Parameter: `username`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=username
userValue=admin
passwordParam=password
referer=http://host.docker.internal:8080/admin/users/3/edit`
* URL: http://host.docker.internal:8080/admin/users/4/edit
  * Node Name: `http://host.docker.internal:8080/admin/users/4/edit ()(fullName,password,role,username)`
  * Method: `POST`
  * Parameter: `username`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=username
userValue=chiefadmin
passwordParam=password
referer=http://host.docker.internal:8080/admin/users/4/edit`
* URL: http://host.docker.internal:8080/login
  * Node Name: `http://host.docker.internal:8080/login ()(password,username)`
  * Method: `POST`
  * Parameter: `username`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=username
userValue=ZAP
passwordParam=password
referer=http://host.docker.internal:8080/login`


Instances: 5

### Solution

This is an informational alert rather than a vulnerability and so there is nothing to fix.

### Reference


* [ https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/ ](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/)



#### Source ID: 3

### [ GET for POST ](https://www.zaproxy.org/docs/alerts/10058/)



##### Informational (High)

### Description

A request that was originally observed as a POST was also accepted as a GET. This issue does not represent a security weakness unto itself, however, it may facilitate simplification of other attacks. For example if the original POST is subject to Cross-Site Scripting (XSS), then this finding may indicate that a simplified (GET based) XSS may also be possible.

* URL: http://host.docker.internal:8080/login
  * Node Name: `http://host.docker.internal:8080/login (password,username)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `GET http://host.docker.internal:8080/login?password=ZAP&username=ZAP HTTP/1.1`
  * Other Info: ``


Instances: 1

### Solution

Ensure that only POST is accepted where POST is expected.

### Reference



#### CWE Id: [ 16 ](https://cwe.mitre.org/data/definitions/16.html)


#### WASC Id: 20

#### Source ID: 1

### [ Information Disclosure - Sensitive Information in URL ](https://www.zaproxy.org/docs/alerts/10024/)



##### Informational (Medium)

### Description

The request appeared to contain sensitive information leaked in the URL. This can violate PCI and most organizational compliance policies. You can configure the list of strings for this check to add or remove values specific to your environment.

* URL: http://host.docker.internal:8080/dashboard%3Fuser=admin
  * Node Name: `http://host.docker.internal:8080/dashboard (user)`
  * Method: `GET`
  * Parameter: `user`
  * Attack: ``
  * Evidence: `user`
  * Other Info: `The URL contains potentially sensitive information. The following string was found via the pattern: user
user`


Instances: 1

### Solution

Do not pass sensitive information in URIs.

### Reference



#### CWE Id: [ 598 ](https://cwe.mitre.org/data/definitions/598.html)


#### WASC Id: 13

#### Source ID: 3

### [ Modern Web Application ](https://www.zaproxy.org/docs/alerts/10109/)



##### Informational (Medium)

### Description

The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

* URL: http://host.docker.internal:8080/login
  * Node Name: `http://host.docker.internal:8080/login`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script>
    var ads = [
        "0% interest personal loans - apply in 2 minutes!",
        "Get a VulnBank Platinum Card - cashback on every swipe.",
        "Refer a friend and earn $50 instantly.",
        "Open a savings account today and earn 5% APY."
    ];
    var adIndex = 0;
    var adTextEl = document.getElementById("ad-text");
    function rotateAd() {
        adTextEl.textContent = ads[adIndex % ads.length];
        adIndex++;
    }
    rotateAd();
    setInterval(rotateAd, 3000);
</script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://host.docker.internal:8080/login%3Flogout
  * Node Name: `http://host.docker.internal:8080/login (logout)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script>
    var ads = [
        "0% interest personal loans - apply in 2 minutes!",
        "Get a VulnBank Platinum Card - cashback on every swipe.",
        "Refer a friend and earn $50 instantly.",
        "Open a savings account today and earn 5% APY."
    ];
    var adIndex = 0;
    var adTextEl = document.getElementById("ad-text");
    function rotateAd() {
        adTextEl.textContent = ads[adIndex % ads.length];
        adIndex++;
    }
    rotateAd();
    setInterval(rotateAd, 3000);
</script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://host.docker.internal:8080/login
  * Node Name: `http://host.docker.internal:8080/login ()(password,username)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script>
    var ads = [
        "0% interest personal loans - apply in 2 minutes!",
        "Get a VulnBank Platinum Card - cashback on every swipe.",
        "Refer a friend and earn $50 instantly.",
        "Open a savings account today and earn 5% APY."
    ];
    var adIndex = 0;
    var adTextEl = document.getElementById("ad-text");
    function rotateAd() {
        adTextEl.textContent = ads[adIndex % ads.length];
        adIndex++;
    }
    rotateAd();
    setInterval(rotateAd, 3000);
</script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`


Instances: 3

### Solution

This is an informational alert and so no changes are required.

### Reference




#### Source ID: 3

### [ User Agent Fuzzer ](https://www.zaproxy.org/docs/alerts/10104/)



##### Informational (Medium)

### Description

Check for differences in response based on fuzzed User Agent (eg. mobile sites, access as a Search Engine Crawler). Compares the response statuscode and the hashcode of the response body with the original response.

* URL: http://host.docker.internal:8080
  * Node Name: `http://host.docker.internal:8080`
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:8080/account
  * Node Name: `http://host.docker.internal:8080/account`
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:8080/admin
  * Node Name: `http://host.docker.internal:8080/admin`
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``

Instances: Systemic


### Solution



### Reference


* [ https://owasp.org/wstg ](https://owasp.org/wstg)



#### Source ID: 1

### [ User Controllable HTML Element Attribute (Potential XSS) ](https://www.zaproxy.org/docs/alerts/10031/)



##### Informational (Low)

### Description

This check looks at user-supplied input in query string parameters and POST data to identify where certain HTML attribute values might be controlled. This provides hot-spot detection for XSS (cross-site scripting) that will require further review by a security analyst to determine exploitability.

* URL: http://host.docker.internal:8080/search%3Fq=test
  * Node Name: `http://host.docker.internal:8080/search (q)`
  * Method: `GET`
  * Parameter: `q`
  * Attack: ``
  * Evidence: ``
  * Other Info: `User-controlled HTML attribute values were found. Try injecting special characters to see if XSS might be possible. The page at the following URL:

http://host.docker.internal:8080/search?q=test

appears to include user input in:
a(n) [input] tag [value] attribute

The user input found was:
q=test

The user-controlled value was:
test`


Instances: 1

### Solution

Validate all input and sanitize output it before writing to any HTML attributes.

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)


#### CWE Id: [ 20 ](https://cwe.mitre.org/data/definitions/20.html)


#### WASC Id: 20

#### Source ID: 3

### [ Username Hash Found ](https://www.zaproxy.org/docs/alerts/10057/)



##### Informational (High)

### Description

A hash of a username (admin) was found in the response. This may indicate that the application is subject to an Insecure Direct Object Reference (IDOR) vulnerability. Manual testing will be required to see if this discovery can be abused.

* URL: http://host.docker.internal:8080/admin/debug/all-data
  * Node Name: `http://host.docker.internal:8080/admin/debug/all-data`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `21232f297a57a5a743894a0e4a801fc3`
  * Other Info: `The hash was an MD5, with value: 21232f297a57a5a743894a0e4a801fc3`
* URL: http://host.docker.internal:8080/admin/users%3Fkey=Sup3rAdmin!2023
  * Node Name: `http://host.docker.internal:8080/admin/users (key)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `21232f297a57a5a743894a0e4a801fc3`
  * Other Info: `The hash was an MD5, with value: 21232f297a57a5a743894a0e4a801fc3`


Instances: 2

### Solution

Use per user or session indirect object references (create a temporary mapping at time of use). Or, ensure that each use of a direct object reference is tied to an authorization check to ensure the user is authorized for the requested object.

### Reference


* [ https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References.html ](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References.html)


#### CWE Id: [ 284 ](https://cwe.mitre.org/data/definitions/284.html)


#### WASC Id: 2

#### Source ID: 3


