# Read Windows Calculator display text via UI Automation.
# Prints candidates as "AutomationId|Name" lines. Exit 0 if any found.

Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

$root = [System.Windows.Automation.AutomationElement]::RootElement
$wins = $root.FindAll(
    [System.Windows.Automation.TreeScope]::Children,
    [System.Windows.Automation.Condition]::TrueCondition
)

$printed = 0
foreach ($w in $wins) {
    $name = ""
    $cls = ""
    try {
        $name = $w.Current.Name
        $cls = $w.Current.ClassName
    } catch { continue }

    # Calculator window: English title, or CJK 小算盤/計算機 (unicode escapes)
    $isCalcTitle =
        ($name -match "Calculator") -or
        ($name -match "[\u5C0F]\u7B97\u76E4") -or
        ($name -match "\u8A08\u7B97\u6A5F") -or
        ($name -match "\u8BA1\u7B97\u5668")

    if (-not $isCalcTitle) { continue }

    Write-Output ("WINDOW|{0}|{1}" -f $cls, $name)

    $all = $w.FindAll(
        [System.Windows.Automation.TreeScope]::Descendants,
        [System.Windows.Automation.Condition]::TrueCondition
    )

    foreach ($el in $all) {
        try {
            $id = $el.Current.AutomationId
            $nm = $el.Current.Name
            if (-not $nm) { continue }

            $interesting =
                ($id -eq "CalculatorResults") -or
                ($id -eq "NormalOutput") -or
                ($id -eq "CalculatorExpression") -or
                ($id -match "Result|Display|Output") -or
                ($nm -match "Display is|^\d") -or
                ($nm -match "\u986F\u793A|\u663E\u793A")

            if ($interesting) {
                Write-Output ("{0}|{1}" -f $id, $nm)
                $printed++
            }
        } catch {
            # ignore
        }
    }

    if ($printed -eq 0) {
        # Fallback dump first text-like nodes
        $n = 0
        foreach ($el in $all) {
            try {
                $id = $el.Current.AutomationId
                $nm = $el.Current.Name
                if ($nm -and $nm.Length -lt 80) {
                    Write-Output ("DEBUG|{0}|{1}" -f $id, $nm)
                    $n++
                    if ($n -ge 40) { break }
                }
            } catch {}
        }
    }

    break
}

if ($printed -eq 0) {
    exit 2
}
exit 0
