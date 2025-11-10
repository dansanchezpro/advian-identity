# Critical Security Issues Found

## ISSUE 1: Weak Password Hashing
Location: UserService.cs Lines 107-112

Current Code:
```csharp
private static string HashPassword(string password)
{
    using var sha256 = SHA256.Create();
    var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password + "salt"));
    return Convert.ToBase64String(hashedBytes);
}
```

Problems:
- Hardcoded salt "salt" instead of random salt
- Direct SHA256 vulnerable to rainbow tables
- No iteration/stretching
- GPU/ASIC attacks succeed in seconds
- All users with same password have identical hash

Risk: Password database breach = all accounts compromised

---

## ISSUE 2: JWT Signature Not Verified  
Location: AuthController.cs Lines 867-938 (ValidateGoogleIdToken)

Current Code:
```csharp
var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
var jsonToken = handler.ReadJwtToken(idToken); // Only READS, doesn't VALIDATE
// Extracts claims without signature check
```

Problems:
- Only decodes JWT, doesn't verify signature
- Any attacker can forge tokens
- Can claim to be any Google user
- No cryptographic validation

Attack: Attacker creates fake token with any googleId/email

---

## ISSUE 3: Race Condition on User Creation
Location: AuthController.cs Lines 788-823 (RegisterWithGoogle)

Current Code:
```csharp
// STEP 1: Check if exists
var existingUser = await _context.Users
    .FirstOrDefaultAsync(u => u.GoogleId == googleId || u.Email == email);

if (existingUser != null)
    return Ok(...); // Thread A passes check here

// STEP 2: Create (RACE CONDITION)
var user = new User { Email = email, ... };
_context.Users.Add(user);
await _context.SaveChangesAsync(); // Thread B also inserting same email
```

Problem: Between check and insert, another user could be created with same email

Attack: Two concurrent requests create accounts with identical email

---

## ISSUE 4: HTTP 200 for Errors
Location: AuthController.cs Lines 749-864 (RegisterWithGoogle)

Current Code:
```csharp
if (string.IsNullOrEmpty(request.IdToken) || ...)
{
    return Ok(new { success = false, error = "..." }); // HTTP 200
}
```

Problems:
- Returns HTTP 200 OK for all errors
- Client cannot distinguish success from failure
- Breaks REST conventions
- Middleware/proxies may not process as error
- Same code for 400/409/500 errors

Impact: Clients can't implement proper error handling

---

## ISSUE 5: SSRF Vulnerability
Location: AuthController.cs Line 428 (ExternalCallback)

Current Code:
```csharp
if (string.IsNullOrEmpty(returnUrl))
{
    return Redirect(...);
}

// ... later ...
return Redirect(returnUrl); // No validation
```

Problem: returnUrl comes from state parameter (user-controlled)
- Could redirect to attacker's site
- Could redirect to internal services
- No whitelist validation

Attack: ?state=aHR0cHM6Ly9ldmlsLmNvbQ== redirects to attacker's site

---

## ISSUE 6: Exception Message Disclosure
Location: AuthController.cs Line 528 (Register endpoint)

Current Code:
```csharp
catch (InvalidOperationException ex)
{
    return BadRequest(new { 
        error = "registration_failed", 
        error_description = ex.Message // Exposes exception message
    });
}
```

Example response:
```json
{
    "error": "registration_failed",
    "error_description": "User with this email already exists"
}
```

Problem: Exception messages reveal system details
- Confirms email addresses in system
- Reveals table/column names
- Helps attackers understand architecture

---

## ISSUE 7: No Rate Limiting
Location: All auth endpoints (login, register, google)

Problem: No protection against brute force attacks
- Attackers can try unlimited passwords
- No account lockout
- No IP blocking

Attack: Brute force password in minutes

---

## ISSUE 8: No Error Logging
Location: All try-catch blocks

Current Code:
```csharp
catch (Exception ex)
{
    return StatusCode(500, ...);
    // No logging - error is invisible
}
```

Problem: Can't debug production issues
- Don't know what went wrong
- Can't detect attack patterns
- No audit trail

---

## SUMMARY

| Issue | Severity | Type | Line(s) |
|-------|----------|------|---------|
| Weak password hashing | CRITICAL | Security | UserService 107-112 |
| JWT signature check missing | CRITICAL | Security | AuthController 867-938 |
| Race condition on user creation | CRITICAL | Security | AuthController 788-823 |
| HTTP 200 for errors | HIGH | Functional | AuthController 749-864 |
| SSRF vulnerability | HIGH | Security | AuthController 241-434 |
| Exception message disclosure | HIGH | Security | AuthController 528 |
| No rate limiting | HIGH | Security | All auth endpoints |
| No error logging | HIGH | Operational | All try-catch blocks |

