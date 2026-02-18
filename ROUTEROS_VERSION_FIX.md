# RouterOS Version Check Fix

## Problem Description

The RouterOS version checking script was incorrectly failing when detecting version `7.22rc1` even though it should pass the minimum requirement of `7.21`.

### Error Message
```
Checking RouterOS version...
Detected RouterOS version: 7.22rc1 (testing) (major: 7, minor: 22rc1)
ERROR: This script requires RouterOS 7.21 or higher
Your version: 7.22rc1 (testing)
Script Error: RouterOS version too old (:error; line 96)
```

## Root Cause

The version comparison logic was treating the minor version as a string (`"22rc1"``) instead of properly parsing the numeric portion (`22`) separately from the pre-release suffix (`rc1`).

When comparing strings:
- `"22rc1" < "21"` would evaluate incorrectly depending on string comparison rules
- The "rc1" suffix was interfering with numeric comparison

## Solution

The fix implements proper semantic version parsing:

1. **Parse major version**: Extract the number before the first dot (e.g., `7` from `7.22rc1`)
2. **Parse minor version**: Extract only the numeric digits after the dot (e.g., `22` from `22rc1`)
3. **Extract channel info**: Capture the pre-release suffix (e.g., `rc1`, `beta1`, `-testing`) for informational purposes
4. **Numeric comparison**: Compare major and minor versions as numbers, not strings

### Comparison Logic

```
Version A >= Version B if:
  - A.major > B.major, OR
  - A.major == B.major AND A.minor >= B.minor
```

### Examples

| Version | Parsed As | >= 7.21? | Reason |
|---------|-----------|----------|--------|
| 7.22rc1 | 7.22 | ✅ YES | 7.22 >= 7.21 (22 > 21) |
| 7.21 | 7.21 | ✅ YES | 7.21 >= 7.21 (equal) |
| 7.21rc1 | 7.21 | ✅ YES | 7.21 >= 7.21 (equal) |
| 7.20 | 7.20 | ❌ NO | 7.20 < 7.21 (20 < 21) |
| 7.20rc1 | 7.20 | ❌ NO | 7.20 < 7.21 (20 < 21) |
| 8.0 | 8.0 | ✅ YES | 8.0 >= 7.21 (8 > 7) |

## Files

- **`routeros-version-check.rsc`** - Fixed RouterOS script with proper version checking
- **`test-version-check.rsc`** - Test suite demonstrating the fix works correctly
- **`ROUTEROS_VERSION_FIX.md`** - This documentation file

## Usage

### Running the Version Check Script

```routeros
/import routeros-version-check.rsc
```

This script will:
1. Display the detected RouterOS version
2. Parse it correctly (including RC/beta/testing suffixes)
3. Compare against minimum required version (7.21)
4. Either succeed or fail with an error message

### Running the Tests

```routeros
/import test-version-check.rsc
```

This will run a comprehensive test suite showing:
- Version parsing tests (extracting major, minor versions correctly)
- Version comparison tests (confirming >= logic works correctly)
- Edge cases (RC versions, beta versions, etc.)

## Key Changes in the Fix

### Before (Broken)
```routeros
# Old code would treat "22rc1" as a single unit
:local minorVersion "22rc1"
# String or naive comparison would fail
```

### After (Fixed)
```routeros
# New code extracts numeric portion
:local minorVersion ""
:local i 0
:while ($i < [:len $afterDot]) do={
    :local char [:pick $afterDot $i ($i + 1)]
    # Check if character is a digit (0-9)
    :if ($char = "0" || $char = "1" || ... || $char = "9") do={
        :set minorVersion ($minorVersion . $char)
    } else={
        # Found non-digit, stop parsing minor version
        :set i [:len $afterDot]
    }
    :set i ($i + 1)
}
# minorVersion is now "22" (numeric string)
:local minorNum [:tonum $minorVersion]  # Convert to number
```

## Testing

The fix has been tested with the following version strings:
- ✅ `7.22rc1` - Correctly parsed as 7.22
- ✅ `7.21` - Correctly parsed as 7.21
- ✅ `7.22beta1` - Correctly parsed as 7.22
- ✅ `7.22-rc1` - Correctly parsed as 7.22
- ✅ `6.49.10` - Correctly parsed as 6.49
- ✅ `8.0` - Correctly parsed as 8.0

All comparisons against minimum version 7.21 now work correctly.

## Integration

To integrate this fix into your existing RouterOS script:

1. Replace your version parsing logic with the code from `routeros-version-check.rsc`
2. Ensure you parse the numeric portion of the minor version separately
3. Use `:tonum` to convert string numbers to integers for comparison
4. Compare major version first, then minor version

## Notes

- Pre-release versions (RC, beta, alpha) are considered equal to their release version for comparison purposes (e.g., 7.22rc1 == 7.22)
- If you need to treat RC versions as less than release versions, additional logic would be needed
- The current fix solves the immediate problem: 7.22rc1 should be >= 7.21

## License

This fix is provided as-is for integration into RouterOS scripts.
