# Error Handling Analysis - Quick Reference

## Critical Issues (5 MUST FIX)

| Issue | Location | Fix |
|-------|----------|-----|
| Weak password hashing | UserService.cs:107-112 | Use BCrypt with cost=12 |
| JWT not verified | AuthController.cs:867-938 | Add signature validation |
| Race condition | AuthController.cs:788-823 | Use database transaction |
| HTTP 200 for errors | AuthController.cs:749-864 | Return 400/409 |
| SSRF vulnerability | AuthController.cs:241-434 | Validate returnUrl |

## High Priority Issues (3 SHOULD FIX)

| Issue | Location | Fix |
|-------|----------|-----|
| No rate limiting | All auth endpoints | Implement 5/15min limit |
| No error logging | All try-catch blocks | Add ILogger injection |
| Exception disclosure | AuthController.cs:528 | Return generic message |

## Edge Cases Not Handled

Frontend:
- Timeout errors (generic message)
- HTTP status differentiation (same message for 400/500)
- JSON deserialization failures (silent)
- Configuration validation missing

Backend:
- SignInAsync exception (Login endpoint)
- SaveChangesAsync exception (multiple)
- AddExternalLoginAsync errors (not checked)
- Query parsing exceptions (not wrapped)

## Files Analyzed

```
Login.razor (616 lines)
- Error display: 83-88
- HandleLogin: 425-486
- Google error: 388-395

Register.razor (938 lines)
- Error display: 136-148
- HandleRegister: 573-720
- Google callback: 722-776

AuthController.cs (1123 lines)
- Login: 115-150
- Register: 473-534
- RegisterWithGoogle: 749-864 [CRITICAL]
- ValidateGoogleIdToken: 867-938 [CRITICAL]
- ExternalCallback: 241-434 [CRITICAL]

UserService.cs (114 lines)
- HashPassword: 107-112 [CRITICAL]
- RegisterUserAsync: 68-91
```

## Error Messages to Users

### Login Page (5 messages)
1. "Please enter your email and password."
2. "Invalid email or password"
3. "No account found with this Google account..."
4. "An error occurred during login. Please try again."
5. "An error occurred during external login..."

### Register Page (8 messages)
1. "Date of birth is required"
2. "You must accept the terms and conditions"
3. "Registration with Google failed. Please try again."
4. "Registration failed. Please try again."
5. "Connected with Google as {email}..."
6. "Failed to retrieve Google account information..."
7. "An unexpected error occurred. Please try again."
8. "Google authentication failed: {errorContent}"

## HTTP Status Codes

Current: 200 OK, 400 Bad Request, 500 Internal Server Error

Should have: 401 Unauthorized, 409 Conflict, 429 Too Many Requests

## Error Types Handled

✓ Empty/missing fields
✓ Invalid credentials
✓ Duplicate email (on API response only)
✓ Age restriction
✓ Token validation (basic claims only)
✓ Network errors (generic)

✗ Timeout errors (generic)
✗ HTTP status differentiation
✗ JSON parsing failures
✗ CORS failures
✗ Token signature verification
✗ Race conditions
✗ Database constraint violations

## Documentation Files

1. **ERROR_ANALYSIS_INDEX.md** - Start here (overview & navigation)
2. **SUMMARY_AND_RECOMMENDATIONS.txt** - Detailed findings & fixes
3. **CRITICAL_SECURITY_ISSUES.md** - 8 security vulnerabilities
4. **ERROR_HANDLING_ANALYSIS_PART1.md** - Frontend analysis
5. **ERROR_HANDLING_ANALYSIS_PART2.md** - Backend analysis

## Action Plan (Priority)

### Week 1 (CRITICAL)
- [ ] Replace password hashing with BCrypt
- [ ] Add JWT signature verification
- [ ] Make user creation atomic
- [ ] Fix HTTP status codes

### Week 2 (HIGH)
- [ ] Validate returnUrl (SSRF fix)
- [ ] Implement rate limiting
- [ ] Add error logging
- [ ] Remove exception exposure

### Week 3 (MEDIUM)
- [ ] Add OIDC state validation
- [ ] Differentiate error messages
- [ ] Add timeout detection
- [ ] Pre-check duplicate emails

## Contact Points (Code Review)

```csharp
// Review These Methods First:

UserService.cs:
  - HashPassword() - CRITICAL
  - RegisterUserAsync() - RACE CONDITION

AuthController.cs:
  - Login() - No SignIn catch
  - Register() - Exception exposure
  - RegisterWithGoogle() - HTTP 200 errors [CRITICAL]
  - ValidateGoogleIdToken() - No signature [CRITICAL]
  - ExternalCallback() - SSRF + race condition [CRITICAL]
  - GetGoogleUserInfo() - Error handling
  - ExchangeGoogleCodeForToken() - Error handling
```

## Testing Checklist

- [ ] Test invalid credentials (should 400)
- [ ] Test duplicate email (should 409, not 200)
- [ ] Test invalid token (should fail verification)
- [ ] Test race condition (concurrent registrations)
- [ ] Test rate limiting (6+ requests/min)
- [ ] Test SSRF (invalid returnUrl)
- [ ] Test timeout (network disconnected)
- [ ] Test age < 13 (should reject)
- [ ] Test Google login error (should show message)
- [ ] Test expired token (should reject)

