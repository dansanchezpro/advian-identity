# Error Handling Analysis - PART 2

## 3. AUTHCONTROLLER.CS KEY ISSUES

### 3.1 Login Endpoint (Lines 115-150)
- No try-catch: SignInAsync exceptions not caught
- Returns HTTP 400 for invalid credentials (correct)
- No logging of failed attempts

### 3.2 Register Endpoint (Lines 473-534)
- Exposes exception message to client via InvalidOperationException
- Age calculation may have leap year issues
- Returns HTTP 400 or 500 for same error

### 3.3 RegisterWithGoogle CRITICAL ISSUE (Lines 749-864)
**RETURNS HTTP 200 OK FOR ALL ERRORS** - Should return 400/409
- Line 759: "All fields are required" returns 200
- Line 769: "Invalid token" returns 200
- Line 794: "User already exists" returns 200  
- Line 804: "Age restriction" returns 200
- Line 862: Generic exception returns 200

**Race Condition (Line 788-795):**
Check for duplicate then insert not atomic - two users could be created with same email

### 3.4 ValidateGoogleIdToken SECURITY ISSUE (Lines 867-938)
**NO SIGNATURE VERIFICATION**
- Only reads JWT, doesn't validate signature
- Token forgery is possible
- Issuer check accepts both HTTP and HTTPS
- No exception logging (Line 933-936)

### 3.5 External Callback Issues (Lines 241-434)
- Exception message exposed to client (Line 432)
- No returnUrl validation (SSRF vulnerability)
- AddExternalLoginAsync failure not checked (Line 354)
- SaveChangesAsync failure not caught (Line 360)

---

## 4. USERSERVICE PASSWORD HASHING - CRITICAL

### Current Implementation (Lines 107-112)
```
private static string HashPassword(string password)
{
    using var sha256 = SHA256.Create();
    var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password + "salt"));
    return Convert.ToBase64String(hashedBytes);
}
```

### CRITICAL SECURITY ISSUES
1. Hardcoded salt "salt" - NOT random
2. SHA256 direct - vulnerable to rainbow tables
3. No iteration - GPU attacks succeed quickly
4. All users with same password = identical hash
5. Attacker can crack all passwords at once

### Attack Example
All users with "password123" produce:
SHA256("password123salt") = abc123...
Attacker cracks one, gets all matching users

### Other UserService Issues (Lines 18-91)
- RegisterUserAsync throws InvalidOperationException for business logic
- SaveChangesAsync not caught (could be DbUpdateException)
- Race condition: Email could be inserted between check and add
- No email format validation
- No password strength validation

---

## 5. HTTP STATUS CODES

### Current Implementation
| Endpoint | Status | Issue |
|----------|--------|-------|
| POST /register-with-google ALL | 200 OK | WRONG - should be 400/409 |
| POST /login success | 200 OK | Correct |
| POST /login invalid | 400 Bad Request | Correct |
| POST /register | 400/500 | Correct for most cases |
| GET /external-callback | 400/200/redirect | Mixed |

### Missing Status Codes
- 401 Unauthorized - Invalid credentials
- 409 Conflict - Duplicate email/user
- 429 Too Many Requests - Rate limiting
- 403 Forbidden - Authorization check

---

## 6. CRITICAL FINDINGS SUMMARY

### Security Vulnerabilities
1. Weak password hashing (SHA256 + hardcoded salt)
2. JWT token forgery possible (no signature check)
3. Race condition on user creation
4. SSRF vulnerability (no returnUrl validation)
5. Exception message exposure to client

### Functional Issues
1. HTTP 200 returns for errors in RegisterWithGoogle
2. No rate limiting
3. No error logging
4. Inconsistent error response formats
5. Age calculation issues

### Edge Cases Missing
1. Timeout handling
2. Network error differentiation
3. JSON parsing failures
4. CORS pre-flight failures
5. Duplicate state decode handling
6. Configuration validation

