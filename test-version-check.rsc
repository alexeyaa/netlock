# Test script for RouterOS version checking logic
# This demonstrates the fix for the version comparison bug

:put "=== RouterOS Version Check Test Suite ==="
:put ""

# Test function to parse and compare versions
:global testVersionParse do={
    :local testVersion $1
    :local expectedMajor $2
    :local expectedMinor $3
    
    :put ("Testing: $testVersion")
    
    # Parse version (same logic as main script)
    :local majorVersion ""
    :local minorVersion ""
    
    :local dotPos [:find $testVersion "." 0]
    :if ([:typeof $dotPos] != "nil") do={
        :set majorVersion [:pick $testVersion 0 $dotPos]
        :local afterDot [:pick $testVersion ($dotPos + 1) [:len $testVersion]]
        
        :set minorVersion ""
        :local i 0
        :while ($i < [:len $afterDot]) do={
            :local char [:pick $afterDot $i ($i + 1)]
            :if ($char = "0" || $char = "1" || $char = "2" || $char = "3" || $char = "4" || \
                $char = "5" || $char = "6" || $char = "7" || $char = "8" || $char = "9") do={
                :set minorVersion ($minorVersion . $char)
            } else={
                :set i [:len $afterDot]
            }
            :set i ($i + 1)
        }
    }
    
    :local majorNum [:tonum $majorVersion]
    :local minorNum [:tonum $minorVersion]
    
    :put ("  Parsed: major=$majorNum, minor=$minorNum")
    :put ("  Expected: major=$expectedMajor, minor=$expectedMinor")
    
    :if ($majorNum = $expectedMajor && $minorNum = $expectedMinor) do={
        :put ("  Result: PASS")
    } else={
        :put ("  Result: FAIL")
    }
    :put ""
}

# Test function to check if version meets minimum requirement
:global testVersionCheck do={
    :local testVersion $1
    :local minMajor $2
    :local minMinor $3
    :local shouldPass $4
    
    :put ("Checking if $testVersion >= $minMajor.$minMinor")
    
    # Parse version
    :local majorVersion ""
    :local minorVersion ""
    
    :local dotPos [:find $testVersion "." 0]
    :if ([:typeof $dotPos] != "nil") do={
        :set majorVersion [:pick $testVersion 0 $dotPos]
        :local afterDot [:pick $testVersion ($dotPos + 1) [:len $testVersion]]
        
        :set minorVersion ""
        :local i 0
        :while ($i < [:len $afterDot]) do={
            :local char [:pick $afterDot $i ($i + 1)]
            :if ($char = "0" || $char = "1" || $char = "2" || $char = "3" || $char = "4" || \
                $char = "5" || $char = "6" || $char = "7" || $char = "8" || $char = "9") do={
                :set minorVersion ($minorVersion . $char)
            } else={
                :set i [:len $afterDot]
            }
            :set i ($i + 1)
        }
    }
    
    :local majorNum [:tonum $majorVersion]
    :local minorNum [:tonum $minorVersion]
    
    # Version comparison
    :local versionOk false
    :if ($majorNum > $minMajor) do={
        :set versionOk true
    } else={
        :if ($majorNum = $minMajor) do={
            :if ($minorNum >= $minMinor) do={
                :set versionOk true
            }
        }
    }
    
    :put ("  Comparison result: " . [:if ($versionOk) do={"meets requirement"} else={"too old"}])
    :put ("  Expected: " . [:if ($shouldPass) do={"meets requirement"} else={"too old"}])
    
    :if ($versionOk = $shouldPass) do={
        :put ("  Test: PASS")
    } else={
        :put ("  Test: FAIL")
    }
    :put ""
}

:put "--- Test 1: Version Parsing ---"
$testVersionParse "7.22rc1" 7 22
$testVersionParse "7.21" 7 21
$testVersionParse "7.22beta1" 7 22
$testVersionParse "7.22-rc1" 7 22
$testVersionParse "7.1" 7 1
$testVersionParse "6.49.10" 6 49

:put "--- Test 2: Version Comparison (min required: 7.21) ---"
# These should PASS (>= 7.21)
$testVersionCheck "7.22rc1" 7 21 true
$testVersionCheck "7.21" 7 21 true
$testVersionCheck "7.21rc1" 7 21 true  
$testVersionCheck "7.22" 7 21 true
$testVersionCheck "7.30" 7 21 true
$testVersionCheck "8.0" 7 21 true

# These should FAIL (< 7.21)
$testVersionCheck "7.20" 7 21 false
$testVersionCheck "7.20rc1" 7 21 false
$testVersionCheck "6.49" 7 21 false
$testVersionCheck "7.1" 7 21 false

:put "=== Test Suite Complete ==="
