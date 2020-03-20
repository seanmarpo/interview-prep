# Web Application Security Interview Notes
A collection of my notes while preparing for Security Engineering positions, specific to web application security. This is a brain dump and collection of many resources in a single place. Yes, there is room for improvement. I am aware. :)

## Vulnerabilities

### OWASP Top 10

1. Injection
    * SQL Injection
    * NoSQL Injection

**Remediations:**
* Parameterized statements
* Validate user input (ensuring types sometimes is enough)
* Migrate to a framework that supports an ORM (Object Relational Mapping)

---

2. Broken Authentication
    * No RBAC(Role-Based Access Control) / Broken RBAC
    * Account bruteforce
    * Weak credential requirements or overly specific credential requirements
    * Poor session management
        * Sessions not invalidated upon logging out
        * Sessions not rotated upon next login

**Remediations:**
* Implement 2FA
    * TOTP, Security Key (Yubikey), or SMS (please do not implement SMS)
* Never ship anything with default credentials
    * Generate a one-time token on boot, use this in a flow to create the initial administrator account
* Limit bruteforce attempts
    * Captcha
    * IP Rate Limiting
    * Account lockout (be careful, this can be abused to lock everyone out)
* Ensure session management is solid
    * In most cases, use the default system that ships with your web framework. It will (most of the time) provide all the requirements for generating and managing sessions securely.

---

3. Sensitive Data Exposure
    * Not using HTTPS
    * Weak crypto primitives (encryption/hashing)
    * Exposing information
        * S3 Buckets/Digital Ocean Spaces/Databases/Key-Value Stores

**Remediations:**
* Ensure a data classification matrix exists - Use this to determine what is sensitive and what is not. Use this as your source of truth when determining how to store data.
* Encrypt sensitive data at rest
    * Use a sane strategy where each "customer" has their own key
* Hash data that is not need to be known (eg. passwords)
    * hash scheme should hash N number of times (pick some arbitrary number)
    * bcrypt, argon2
    * Each user should have a randomly generated salt
    * If you're feeling extra secure, have an application-level pepper value that is used for all hashing
* Only ever communicate over a secure channel (HTTPS or TLS tunnels)

---

4. XML External Entities
    * Are XML Entities allowed?
    * Are XSL Transformations secured?
    * Is a data format used that resembles or is based on XML?

**Remediations:**
* Standardize your XML parsing functions into a single place/library
    * Ensure that library uses a parser which supports disabling entities and performs depth checks
    * Only allow the use of this single XML parser library which has been deemed "secure"
* If the above is not possible, refer to the [OWASP XXE Prevention Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.md)

---

5. Broken Access Control
    * Bypassing access control checks
    * (I)DOR - (In)direct Object Reference
    * Broken CORS Configuration
    * Unauthenticated endpoints
    * Token manipulation (JWT/etc)

**Remediations:**
* All endpoints should be authenticated by default, only static content (JS, CSS, images) should be available without authentication
    * If you can enforce auth on static content, by all means, do that. But it is typically harder.
* Ensure permission checks are being performed always
    * Always check that the user has permission to view what they are requesting (and not just checking that they are logged in)
    * Implement Role-Based Access Control (RBAC)
* Ensure default webserver files and directory listing is disabled on your web-server
* Ensure tokens are properly validated
    * For JWT - Check that the audience matches what you are expecting
    * For JWT - Check that the token is not expired
    * Ensure tokens are properly invalidated upon logout/expiry

---

6. Security Misconfiguration
    * Missing patches
    * Default credentials
    * Verbose error messages (stacktrace/verbose messages)
    * Security settings not enabled in framework
    * Missing security headers

**Remediations:**
* Ensure a system exists which regularly patches or "recycles" the environment with an up-to-date version
* Ensure configurations are reviewed automatically for known anti-patterns (eg. public S3 buckets)
* Implement extra hardening by implementing some of the many HTTP Security headers

---

7. Cross-Site Scripting (XSS)
    * Reflected XSS
        * User input is reflected in response and is not sanitized/escaped
    * Stored XSS
        * Application stores malicious input and responds at a later time with payload
    * DOM-based XSS
        * Javascript frameworks, single-page apps, and APIs that dynamically include attacker-controllable data

**Remediations:**
* Use a web framework that encodes correctly by default (most frameworks do this for you now)
* Output encode. Always output encode. Correctly encode for the context the data is being placed into.
    * URLs - URL Encode
    * Document (reflected in the HTML response) - HTML Encode
    * Javascript - JS Escape or URL Encode (data will get weird with URL encoding though)
    * Refer to the [OWASP Cheatsheet on XSS Prevention](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.md)
* In situations where rich text is needed, use a standard sanitization library. But be ever vigilant for new bypasses and security issues related to the library
    * [DomPurify](https://github.com/cure53/DOMPurify)
* Enable CSP (and hope you do it correctly)

---

8. Insecure Deserialization
    * Objects, cookies, form parameters, and authentication tokens
    * Objects are serialized for transit between applications

**Remediation:**
* Perform integrity checking on serialized data to ensure it can be trusted
    * AES GCM - Encrypts the data and also ensures integrity via a signature
    * Worst case, HMAC the serialized data
* Ensure there is extra logging around serialization functions
    * Flag on large quantities on serialization/deserialization calls

---

9. Using Components with Known Vulnerabilities
    * Application dependencies
    * Operating system patches
    * Security advisories for frameworks, OS, or other pieces of the application

**Remediation:**
* Ensure application dependencies are regularly checked for updates/vulnerabilities
    * CI/CD is a great place to have this check run
    * Snyk, XRay, npm audit, etc
* Ensure an OS-level patching system is in place
    * Create a system where the environment is tore down regularly and rebuilt with updated images
    * Scheduled downtime for patching

---

10. Insufficient Logging & Monitoring
    * High-value events are not logged
        * Logins, failed authentication, heavy transactions
    * Application logs generate logs which are not clear
    * Application logs are not monitored
    * Application does not alert/detect attacks in real-time

**Remediation:**
* Ensure a centralized logging solution exists for your application/services
    * All logs should be aggregated here and automation should be able to flag on "events" worth investigating
* Ensure logging is part of the development process and is reviewed by security

### Other Web Vulnerabilities

* Cross-Site Request Forgery (CSRF)
    * The ability to make a state-changing action on another website via a simple request. This abuses the fact that the browser will always send cookies to the website you are making a request to. This allows a malicious site to trick a user into making a state-changing action on a different site (in the context of the user) by submitting a form or having an AJAX request auto-run when a page is visited.

**Remediation:**
* CSRF Tokens
    * A randomized header value (nonce) that is assigned when a session is established with a website
    * A nonce that is submitted with every request that is tied to a user's session
* Same-Site Cookies
    * Browser security feature that blocks sending cookies to third-party websites (when the web application sets the cookie this way)
    * `Set-Cookie: key=value; HttpOnly; SameSite=strict` - This cookie is only sent when using the web application in question. Whenever it is requested as a third-party, the cookie is not sent.'
    * `Set-Cookie: key=value; HttpOnly; SameSite=lax` - This cookie is sent on anchor tags, link tags, and GET requests
* Double Submit Cookie
    * Set a cookie which contains a sufficiently random value
    * Ensure each request also includes a parameter with the same value as the cookie
    * Rationale: Another origin cannot read the cookie value of another origin, therefore they cannot predict the required parameter value for each request.
* Custom Request Header
    * Include an arbitrary HTTP header with each request (eg. `X-Requested-With: XMLHttpRequest`)
    * Other domains cannot set an HTTP header for an Ajax request without an improper CORS configuration
    * Does not protect against `<form>` elements or anything submitted via an HTML flow

---

* Server-Side Request Forgery
    * The ability to make a web application make an HTTP request where the user controls all or part of the request
        * Full Control of URL
            * "Poor Man's Port Scanner" - You can force a web app to make a request to local resources and attempt to scan for interesting ports that are open
            * Protocol Smuggling - You can attempt to interact with resources that have an HTTP-like protocol (eg. Redis)
            * IaaS/PaaS internal resources
                * AWS / Azure Metadata URL (169.254.169.254)
            * Authenticated requests - You can exfiltrate internal authentication tokens to an external resource where those tokens can be stolen
        * Partial Control
            * Path traversal (eg. dots and slashes) to access endpoints maybe not externally facing
    * DNS Rebinding
        * The ability to abuse DNS to bypass SSRF validation
        * Respond to first DNS request with valid IP address, respond to second DNS request with an internal IP (or some other IP)
* Open Redirect
    * The ability to control the redirect location for a web application (typically to another website)
    * Useful for phishing, reputational damage, or SEO shenanigans
* CSV Injection
    * The ability to inject arbitrary formulas into a CSV export.
    * Microsoft Excel will kindly automatically execute specific formulas on sheet load/sheet update leading to cases of backdooring CSVs or other local command execution on a customer's computer
        * Most of these cases are protected with numerous pop-ups and other warnings
* GraphQL Injection
    * DOS - Can embed objects that reference objects that reference objects... and so on. Causes the GraphQL parser to spin indefinitely or just slow the server down
    * Introspection - Can use GraphQL to expose the database schema via GraphQL queries
    * Injection - GraphQL is typically converted to another SQL-like language on the backend, so you can achieve SQLi and other forms of DB injection via GraphQL
* Web Sockets
    * Not validating origin headers
        * Allows arbitrary origins to establish a web socket with your web socket server
    * Missing Authentication
        * Web sockets have concept of state. Typically, a session or authorization token is validated before being allowed to establish a socket. Ensure this is the case.
* (Distributed) Denial of Service (DDoS)
    * The ability to cause an application to stop responding or "hang" indefinitely or for an extended period of time.
    * Network level
        * Flooding applications/networking equipment with high loads of traffic
    * Application level
        * Triggering a function of a web application that causes a thread to halt for an extended period of time
        * Triggering a function of a web application that causes the application to crash entirely
* Other lower-level attacks
    * Most of these attacks are outside of the scope of a web application vulnerability but are still worth knowing for breadth of knowledge
        * Memory Corruption
        * Buffer Overflow
        * Integer Overflow
        * Type Confusion
        * Use After Free (UAF)
* For most other types of attacks and potential attack payloads, use [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
    * When putting this together, this source was referenced extensively. I cannot give enough thanks to those that work on that project.

## Browser Security Concepts

* Same Origin Policy (SOP)
    * Restricts how content can be loaded from other origins and restricts how content from other origins can interact with content on your current origin
    * Origins must match for JS to be able to directly interact with the DOM
    * Cross-origin writes are typically allowed (refer to CORS) - primarily for "simple requests" otherwise they pre-flight
    * Cross-origin reads are typically disallowed, but embedding may leak data
    * Cross-origin embedding is typically allowed
        * The following items can all be embedded cross-origin:
            * JS, CSS, images, video, audio, applets (object, embed, applet), fonts, frames
* Cross-Origin Resource Sharing (CORS)
    * Allows websites to make cross-origin requests without breaking the SOP model
    * The server being requested returns a collection of special HTTP Headers which define what cross-origin requests are allowed (explained below)
        * If no CORS headers are returned, it is assumed the server cannot have cross-origin requests made to it (an error is shown in the JS Console)
    * Uses extra headers (`Access-Control-Allow-Origin`) to define what origin is allowed to make cross-origin requests
    * Employs other headers to define what headers can also be included in the cross-origin request
        * `Access-Control-Allow-Methods` - What methods can be used cross-origin
        * `Access-Control-Allow-Headers` - What headers can be sent cross-origin
        * `Access-Control-Max-Age` - How long until you need to make another pre-flighted request
    * "Simple requests" do not trigger a pre-flight request
        * Methods: `GET`, `HEAD`, `POST`
    * All other requests trigger a pre-flight request which is an HTTP `OPTIONS` request to determine the CORS requirements of the cross-origin site being requested
* Security Headers
    * X-Frame-Options
        * Controls the ability for other websites to frame your content
        * `deny` - Cannot render within a frame
        * `sameorigin` - Can only frame from the same origin
        * `allow-from: DOMAIN` - Allows framing only from DOMAIN
    * HTTP Strict Transport Security (HSTS)
        * Controls whether a site should ONLY be loaded via HTTPS
        * Only works over HTTPS connections, HTTP connections ignore this header
    * X-XSS-Protection
        * Controls the XSS auditor in the browser
        * `0` - Auditor is disabled
        * `1` - Auditor is enabled, will attempt to sanitize attacks
        * `1; mode=block` - Auditor is enabled, will block rendering of pages containing XSS attacks
        * `1; report=https://url/to/report-to` - Auditor is enabled, will sanitize attacks and report to the URL provided
    * X-Content-Type-Options
        * Controls whether the browser will attempt to MIME-sniff the content and adjust the MIME-type on-the-fly
        * `nosniff` - Tells the browser to not guess the MIME-type of the content (even if it looks like something else)
    * Content-Security-Policy (CSP)
        * Controls many aspects of the security of your page and can prevent multiple types of security issues. It also means CSP can also drastically break your website, so test thoroughly and extensively.
* Subresource Integrity (SRI)
    * Ensures content fetched by your browser matches a cryptographic hash
    * Extremely useful when fetching JS/CSS payloads from a CDN or resource you do not control

## Cryptography

