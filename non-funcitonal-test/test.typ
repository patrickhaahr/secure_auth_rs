#set page(paper: "a4", margin: 2cm)
#set text(font: "JetBrains Mono", size: 11pt)
#set heading(numbering: "1.1")

#align(center)[
  #text(20pt, weight: "bold")[
    Secure Auth RS - Non-Functional Test Script
  ]
  
  #v(1em)
  #text(14pt)[
    Three-Phase Authentication System Testing Guide
  ]
  
  #v(2em)
  #text(12pt)[
    Version: 1.0 \
    Date: #datetime.today().display("[month repr:long] [day], [year]") \
    Tester: #text("_________________________")
  ]
]

#v(2em)
= Test Environment Setup

== Prerequisites
- Web browser (Chrome, Firefox, Safari, or Edge)
- Internet connection
- TOTP authenticator app (Aegis, Authy, etc.) MUST SUPPORT SHA512
- Rust must be installed on System. Follow the instructions here: https://rust-lang.org/tools/install/
- If using unix-like OS (Linux, MacOS, etc.), you can run this: 
```curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh ```
- Git clone repo if you haven't already
- ``` git clone https://github.com/patrickhaahr/secure_auth_rs.git ```
- ``` cd secure_auth_rs/ ```
- ``` cargo run ```

- Test URL: https://127.0.0.1:3443

== Browser Security Settings
- Ensure JavaScript is enabled
- Accept TLS certificates if using local development
- Disable password managers for accurate testing

= Test Scenarios

== 1. User Registration Flow

=== Step 1: Navigate to Registration
1. Open browser and navigate to the application URL
2. Click on "Create Account" button
3. Verify registration page loads correctly

=== Step 2: Complete Registration
1. Click "Generate Account ID" button
2. Copy the generated Account ID
3. Click on the "Login" button

== 2. User Login Flow

=== Step 1: Navigate to Login
1. Open browser and navigate to application URL
2. Click on "Continue" button

=== Step 2: Enter Credentials
1. Enter your Account Id
2. Click "Login" button

=== Step 3: First time TOTP authentication Setup
1. click on the "Setup TOTP" button
2. Veryify TOTP setup page loads correctly and can see QR code
3. Scan the QR code with your authenticator app
4. Enter the 6-digit TOTP code from your authenticator app
3. Click "Verify" button

=== Step 4: First time CPR number authentication setup
1. Enter your CPR number - format: DDMMYY-XXXX
2. Click "Submit CPR" button

=== Step 5: Successful Login
1. Verify login page loads correctly
2. Click "Admin Panel" button
3. Verify "Access Denied" message appears
4. Click "Back to Dashboard" button
5. Verify dashboard loads correctly
6. Click "Logout" button
7. Verify logout page loads correctly

=== Expected Results
- Login form validates correctly
- TOTP prompt appears after credential validation
- Successful authentication redirects to dashboard
- JWT token is issued (check browser storage)

== 3. Verified Account Login Flow

=== Step 1: Navigate to Login
1. Open browser and navigate to application URL
2. Make sure you are in index.html page: https://127.0.0.1:3443/

=== Step 2: Enter Account ID
1. Enter your Account ID (from a previously verified account)
2. Click "Login" button

=== Step 3: Verified User Authentication
1. Verify login page detects account as verified
2. Verify TOTP and CPR input fields appear simultaneously
3. Enter the 6-digit TOTP code from your authenticator app
4. Enter your CPR number - format: DDMMYY-XXXX
5. Click "Confirm" button

=== Expected Results
- Login form recognizes verified account status
- Both TOTP and CPR fields are required
- No setup prompts appear (unlike first-time login)
- Successful authentication with both factors redirects to dashboard
- JWT token is issued (check browser storage)
- Session is established correctly

== 4. Security Testing

=== CSRF Protection
1. Login to the application
2. Open new browser tab/window
3. Attempt to submit form via external site or direct POST request
4. Verify CSRF token validation prevents attack

=== Rate Limiting
1. Attempt multiple failed login attempts (>5)
2. Verify rate limiting activates
3. Check error messages and time delays

=== TLS Security
1. Verify HTTPS connection is established
2. Check certificate validity
3. Ensure no mixed content warnings

=== Session Management
1. Login successfully
2. Close browser and reopen
3. Verify session persistence/expiration as expected
4. Test logout functionality

= Test Results

== Pass/Fail Criteria

#table(
  columns: (auto, 1fr, 1.5cm, auto),
  stroke: (x, y) => (
    top: if y == 0 { 2pt } else { 1pt },
    bottom: 1pt,
    left: 1pt,
    right: 1pt,
  ),
  fill: (x, y) => if y == 0 { rgb("#e8e8e8") } else { white },
  align: (left, left, center, left),
  
  [*Test*], [*Description*], [*Status*], [*Notes*],
  
  [Registration], [Complete user registration flow], [☐ ☐], [],
  [Login], [Authentication with TOTP], [☐ ☐], [],
  [CPR Auth], [CPR validation and authorization], [☐ ☐], [],
  [CSRF], [CSRF protection verification], [☐ ☐], [],
  [Rate Limit], [Rate limiting effectiveness], [☐ ☐], [],
  [TLS], [Secure connection verification], [☐ ☐], [],
  [Performance], [Response time benchmarks], [☐ ☐], [],
)
