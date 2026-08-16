# Invoke Windows Calculator buttons via UI Automation (no keyboard focus required).
# Usage: powershell -STA -File invoke-calculator-keys.ps1 -Keys "12+34="
param(
    [Parameter(Mandatory = $true)]
    [string]$Keys
)

Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

function Find-CalculatorWindow {
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $wins = $root.FindAll(
        [System.Windows.Automation.TreeScope]::Children,
        [System.Windows.Automation.Condition]::TrueCondition
    )
    foreach ($w in $wins) {
        try {
            $name = $w.Current.Name
            if (
                ($name -match "Calculator") -or
                ($name -match "[\u5C0F]\u7B97\u76E4") -or
                ($name -match "\u8A08\u7B97\u6A5F") -or
                ($name -match "\u8BA1\u7B97\u5668")
            ) {
                return $w
            }
        } catch {}
    }
    return $null
}

function Find-DescendantById($window, [string]$automationId) {
    $cond = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::AutomationIdProperty,
        $automationId
    )
    return $window.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $cond)
}

function Invoke-Element($element) {
    if ($null -eq $element) { return $false }
    try {
        $pattern = $element.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
        if ($null -eq $pattern) { return $false }
        $pattern.Invoke()
        return $true
    } catch {
        return $false
    }
}

# Case-insensitive hashtable — keep one entry per logical key.
$map = @{
    "0" = "num0Button"
    "1" = "num1Button"
    "2" = "num2Button"
    "3" = "num3Button"
    "4" = "num4Button"
    "5" = "num5Button"
    "6" = "num6Button"
    "7" = "num7Button"
    "8" = "num8Button"
    "9" = "num9Button"
    "+" = "plusButton"
    "-" = "minusButton"
    "*" = "multiplyButton"
    "/" = "divideButton"
    "=" = "equalButton"
    "." = "decimalSeparatorButton"
    "c" = "clearButton"
    "e" = "clearEntryButton"
}

$window = Find-CalculatorWindow
if ($null -eq $window) {
    Write-Output "ERROR|calculator window not found"
    exit 2
}

Write-Output ("WINDOW|{0}" -f $window.Current.Name)

foreach ($ch in $Keys.ToCharArray()) {
    $s = ([string]$ch).ToLowerInvariant()
    if ($s -match "\s") { continue }
    if ($s -eq "x") { $s = "*" }
    if (-not $map.ContainsKey($s)) {
        Write-Output ("ERROR|unsupported key: {0}" -f $ch)
        exit 3
    }
    $id = $map[$s]
    $el = Find-DescendantById $window $id
    if (-not (Invoke-Element $el)) {
        Write-Output ("ERROR|failed to invoke {0} for key {1}" -f $id, $s)
        exit 4
    }
    Write-Output ("OK|{0}|{1}" -f $s, $id)
    Start-Sleep -Milliseconds 80
}

exit 0
