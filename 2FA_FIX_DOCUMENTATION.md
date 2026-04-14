# 2FA Setup Fix - Complete Implementation

## Problem Summary
Users could see the 2FA QR code during setup, but when they tried to verify their TOTP code, the setup would fail with:
```
"Failed to enable 2FA. Try again or contact admin."
```

## Root Cause Analysis
**Critical Database Schema Issue**: The `users.two_factor_enabled` column was defined as:
```sql
two_factor_enabled tinyint(1) NOT NULL
```
Without a DEFAULT value. This caused:
- INSERT statements without explicit `two_factor_enabled` values to fail
- UPDATE queries to affect 0 rows (user records weren't properly created)
- The `set_user_2fa()` function to return False because `cur.rowcount == 0`

## Complete Solution

### 1. Database Schema Fix
**File**: MySQL database directly + migration file
**Change**: Added DEFAULT 0 to column:
```sql
ALTER TABLE users MODIFY COLUMN two_factor_enabled tinyint(1) NOT NULL DEFAULT 0;
```
**Impact**: All new or existing users now have a default 2FA disabled state

### 2. Enhanced Error Logging
**File**: `src/database.py`

Added comprehensive logging to `set_user_2fa()` function to detect:
- Encryption failures with specific warnings about missing ENCRYPTION_KEY
- Database connection failures
- When UPDATE affects 0 rows (user not found)
- Full exception tracebacks with `exc_info=True`

```python
def set_user_2fa(user_id: str, secret: str, backup_codes_json: Optional[str] = None) -> bool:
    # ... connection check ...
    try:
        enc_secret = _encrypt_data(secret) if secret is not None else None
        if secret and enc_secret is None:
            logger.error("set_user_2fa: Encryption failed for TOTP secret (user_id=%s). ENCRYPTION_KEY may not be configured.", user_id)
            return False
        # ... rest of implementation ...
        if rows_affected == 0:
            logger.warning("set_user_2fa: UPDATE affected 0 rows. User may not exist (user_id=%s)", user_id)
            return False
        logger.info("set_user_2fa: Successfully updated 2FA for user_id=%s", user_id)
        return True
    except Exception as exc:
        logger.error("set_user_2fa: MySQL error for user_id=%s: %s", user_id, exc, exc_info=True)
        return False
```

### 3. Enhanced API Route Logging
**File**: `web/app.py` - `/2fa/setup` POST handler

Added logging at critical points:
- TOTP verification success/failure
- Database call attempts
- Successful 2FA setup completion
- Failure point identification for debugging

```python
if totp.verify(str(code or "").strip(), valid_window=1):
    logger.info("2FA TOTP verification passed for user_id=%s", pre_id)
    # ... backup code generation ...
    logger.info("Calling set_user_2fa for user_id=%s", pre_id)
    if db.set_user_2fa(pre_id, secret, backup_json):
        logger.info("set_user_2fa succeeded for user_id=%s", pre_id)
        # ... login completion ...
        logger.info("2FA setup completed successfully for user_id=%s", pre_id)
        return render_template("show_backup_codes.html", backup_codes=backup_plain)
    else:
        logger.error("set_user_2fa failed for user_id=%s", pre_id)
        flash("Failed to enable 2FA. Try again or contact admin.", "error")
        return redirect(url_for("login"))
else:
    logger.warning("2FA TOTP verification failed for user_id=%s (invalid code)", pre_id)
    flash("Invalid code. Try again.", "error")
    return redirect(url_for("two_factor_setup"))
```

### 4. Migration File Created
**File**: `migrations/002_fix_2fa_schema.py`

Idempotent migration that can be run during deployment to apply the schema fix to any existing installations:
```python
ALTER TABLE users 
MODIFY COLUMN two_factor_enabled tinyint(1) NOT NULL DEFAULT 0
```

## Verification Testing

All 6 critical 2FA operations verified:

✅ **TEST 1: Encryption/Decryption**
- TOTP secrets encrypt and decrypt correctly with Fernet

✅ **TEST 2: User Creation**
- Users can be created with 2FA disabled by default

✅ **TEST 3: 2FA Setup Persistence**
- `set_user_2fa()` returns True
- Encrypted secrets stored in database
- Encrypted backup codes stored in database
- `two_factor_enabled` flag set to 1

✅ **TEST 4: TOTP Verification**
- Generated 6-digit codes pass verification
- Time-window validation works

✅ **TEST 5: Backup Code Marking**
- Backup codes can be marked as used
- Prevents replay attacks

✅ **TEST 6: Admin 2FA Reset**
- Admin can reset user 2FA
- All 2FA data cleared and disabled

## User Flow After Fix

1. **User Login** → Password verified ✓
2. **2FA Setup Page** → QR code generated ✓ (was already working)
3. **Scan QR Code** → Authenticator app generates codes ✓
4. **Enter TOTP Code** → **(NOW WORKS)** ✅
5. **Verify Code** → Persisted to database ✓
6. **Show Backup Codes** → One-time display ✓
7. **Login with 2FA** → TOTP or backup codes accepted ✓

## Files Modified

| File | Changes |
|------|---------|
| `src/database.py` | Enhanced logging in `set_user_2fa()` |
| `web/app.py` | Enhanced logging in `/2fa/setup` POST handler, added missing error handler |
| `migrations/002_fix_2fa_schema.py` | New migration file |
| MySQL Database | Applied schema fix directly |

## Deployment Instructions

1. Apply migration if using existing database:
```bash
python migrations/002_fix_2fa_schema.py
```

2. Verify schema was updated:
```sql
DESCRIBE users;  -- Look for: two_factor_enabled tinyint(1) NOT NULL DEFAULT 0
```

3. Test 2FA flow end-to-end

## Technical Details

**Encryption**: Uses Fernet symmetric encryption with `QSS_ENCRYPTION_KEY` from environment
**TOTP**: Uses pyotp library with 30-second windows and ±1 time-step tolerance
**Backup Codes**: 10 one-time use codes, SHA-256 hashed, displayed only once
**Rate Limiting**: 10 attempts per minute on 2FA login endpoint
