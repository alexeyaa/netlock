# Quick Integration Guide

## Problem
RouterOS version "7.22rc1" was incorrectly failing version check for minimum "7.21"

## Quick Fix

Replace your version checking code with this pattern:

```routeros
# Parse version to extract numeric portions
:local majorVersion ""
:local minorVersion ""
:local dotPos [:find $versionString "." 0]

:if ([:typeof $dotPos] != "nil") do={
    # Extract major version (before dot)
    :set majorVersion [:pick $versionString 0 $dotPos]
    
    # Extract numeric part of minor version (after dot, digits only)
    :local afterDot [:pick $versionString ($dotPos + 1) [:len $versionString]]
    :set minorVersion ""
    
    :local i 0
    :while ($i < [:len $afterDot]) do={
        :local char [:pick $afterDot $i ($i + 1)]
        # Check if character is a digit
        :if ($char = "0" || $char = "1" || $char = "2" || $char = "3" || \
            $char = "4" || $char = "5" || $char = "6" || $char = "7" || \
            $char = "8" || $char = "9") do={
            :set minorVersion ($minorVersion . $char)
        } else={
            # Stop at first non-digit
            :set i [:len $afterDot]
        }
        :set i ($i + 1)
    }
}

# Convert to numbers and compare
:local majorNum [:tonum $majorVersion]
:local minorNum [:tonum $minorVersion]

:local versionOk false
:if ($majorNum > $requiredMajor) do={
    :set versionOk true
} else={
    :if ($majorNum = $requiredMajor) do={
        :if ($minorNum >= $requiredMinor) do={
            :set versionOk true
        }
    }
}
```

## Key Points

1. **Extract numeric portion only** from minor version string
2. **Convert to numbers** using `:tonum` before comparing
3. **Compare major first**, then minor if major versions equal

## Test Your Integration

```routeros
# These should all pass for minimum 7.21:
"7.22rc1"   → 7.22 → PASS
"7.21"      → 7.21 → PASS
"7.21rc1"   → 7.21 → PASS
"8.0"       → 8.0  → PASS

# These should fail for minimum 7.21:
"7.20"      → 7.20 → FAIL
"7.20rc1"   → 7.20 → FAIL
"6.49"      → 6.49 → FAIL
```

## Complete Example

See `routeros-version-check.rsc` for a complete working script.
See `test-version-check.rsc` to run tests.
See `ROUTEROS_VERSION_FIX.md` for detailed documentation.
