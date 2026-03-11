Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
Add-Type -AssemblyName System.Windows.Forms

param(
    [string]$procName,
    [string]$target,
    [string]$replacement
)

$procs = Get-Process -Name $procName -ErrorAction SilentlyContinue
if (-not $procs) {
    Write-Output 'No notepad process found'
    exit 1
}

$proc = $procs | Select-Object -First 1
$hWnd = $proc.MainWindowHandle
if (-not $hWnd) {
    Write-Output 'Notepad has no main window handle'
    exit 1
}

$root = [System.Windows.Automation.AutomationElement]::FromHandle($hWnd)
if (-not $root) {
    Write-Output 'Failed to get AutomationElement from handle'
    exit 2
}

Write-Output "Searching UIA tree under $procName (PID $($proc.Id)) for text pattern..."

$all = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)

$found = $false

for ($i = 0; $i -lt $all.Count; $i++) {
    $el = $all.Item($i)
    $name = $el.Current.Name

    # Try ValuePattern first
    try {
        $vp = $null
        $vp = $el.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
    } catch { $vp = $null }

    if ($vp -ne $null) {
        $val = $vp.Current.Value
        if ($val -and $val.Contains($target)) {
            Write-Output "UIA Object Found: $name - Attempting Text Swap via ValuePattern..."
            try {
                $new = $val.Replace($target, $replacement)
                $vp.SetValue($new)
                Write-Output "ValuePattern.SetValue succeeded on $name"
                exit 0
            } catch {
                Write-Error "ValuePattern.SetValue failed: $_"
            }
        }
    }

    # Try TextPattern
    try {
        $tp = $null
        $tp = $el.GetCurrentPattern([System.Windows.Automation.TextPattern]::Pattern)
    } catch { $tp = $null }

    if ($tp -ne $null) {
        try {
            $doc = $tp.DocumentRange
            $full = $doc.GetText(-1)
            if ($full -and $full.Contains($target)) {
                Write-Output "UIA Object Found: $name - Attempting Text Swap via TextPattern (fallback to Value/SendKeys)..."
                # Prefer ValuePattern if available on same element
                try {
                    $vp2 = $el.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
                    if ($vp2 -ne $null) {
                        $new = $full.Replace($target, $replacement)
                        $vp2.SetValue($new)
                        Write-Output "ValuePattern.SetValue succeeded on $name (via TextPattern content)"
                        exit 0
                    }
                } catch {}

                # Fallback: set focus and send keys (select all then replace)
                $el.SetFocus()
                Start-Sleep -Milliseconds 50
                [System.Windows.Forms.SendKeys]::SendWait('^{a}')
                Start-Sleep -Milliseconds 50
                [System.Windows.Forms.Clipboard]::SetText($full.Replace($target, $replacement))
                [System.Windows.Forms.SendKeys]::SendWait('^v')
                Write-Output "SendKeys fallback attempted on $name"
                exit 0
            }
        } catch {
            # ignore and continue
        }
    }
}

Write-Output "No UIA element containing '$target' was found under Notepad"
exit 3
