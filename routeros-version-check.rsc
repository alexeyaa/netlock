# RouterOS Version Check Script
# This script properly checks RouterOS version including RC/beta/alpha releases
# 
# Bug fix: Previously "7.22rc1" was incorrectly detected as older than "7.21"
# because the version comparison was treating "22rc1" as a string.
#
# The fix: Parse numeric portion separately from pre-release suffix

:local minMajor 7
:local minMinor 21

:put "Checking RouterOS version..."

# Get system version
:local rosVersion [/system resource get version]
:put ("Detected RouterOS version: $rosVersion")

# Extract major version and minor version with better parsing
:local majorVersion
:local minorVersion  
:local versionChannel ""

# Parse version string (format: "X.YY" or "X.YYrcN" or "X.YY-beta")
:if ([:len $rosVersion] > 0) do={
    # Split by first dot to get major version
    :local dotPos [:find $rosVersion "." 0]
    :if ([:typeof $dotPos] != "nil") do={
        :set majorVersion [:pick $rosVersion 0 $dotPos]
        
        # Get everything after the dot
        :local afterDot [:pick $rosVersion ($dotPos + 1) [:len $rosVersion]]
        
        # Extract numeric portion of minor version (before any letter/dash)
        :set minorVersion ""
        :local i 0
        :while ($i < [:len $afterDot]) do={
            :local char [:pick $afterDot $i ($i + 1)]
            # Check if character is a digit (0-9)
            :if ($char = "0" || $char = "1" || $char = "2" || $char = "3" || $char = "4" || \
                $char = "5" || $char = "6" || $char = "7" || $char = "8" || $char = "9") do={
                :set minorVersion ($minorVersion . $char)
            } else={
                # Found non-digit, extract channel info
                :set versionChannel [:pick $afterDot $i [:len $afterDot]]
                :set i [:len $afterDot]
            }
            :set i ($i + 1)
        }
    }
}

:put ("  (major: $majorVersion, minor: $minorVersion" . \
      [:if ([:len $versionChannel] > 0) do={" $versionChannel"} else={""}] . ")")

# Convert to numbers for comparison
:local majorNum [:tonum $majorVersion]
:local minorNum [:tonum $minorVersion]

# Version comparison logic
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

# Report result
:if (!$versionOk) do={
    :put ("ERROR: This script requires RouterOS $minMajor.$minMinor or higher")
    :put ("Your version: $rosVersion")
    :error "RouterOS version too old"
} else={
    :put ("OK: RouterOS version $rosVersion meets minimum requirement ($minMajor.$minMinor)")
}
