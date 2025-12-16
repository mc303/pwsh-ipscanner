<#
    Fast WPF IP Scanner (Sorted & Filtered)
    Features: Natural IP Sorting, Alive Filter, Multithreading, Thread Limit
#>

# Load WPF and System assemblies
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

# ==========================================
# 1. SETTINGS & JSON HANDLING
# ==========================================
$ScriptPath = $PSScriptRoot
if (-not $ScriptPath) { $ScriptPath = Get-Location }
$SettingsFile = Join-Path $ScriptPath "scanner_settings.json"

$DefaultSettings = @{
    "ThreadLimit"  = 50
    "PortsToScan" = "80, 443, 3389"
    "LastRange"   = "192.168.1.1-254"
}

Function Get-Settings {
    if (Test-Path $SettingsFile) {
        try {
            $json = Get-Content $SettingsFile -Raw | ConvertFrom-Json
            foreach ($key in $DefaultSettings.Keys) {
                if ($null -eq $json.$key) { 
                    $json | Add-Member -MemberType NoteProperty -Name $key -Value $DefaultSettings.$key 
                }
            }
            return $json
        } catch { return [PSCustomObject]$DefaultSettings }
    } else {
        $DefaultSettings | ConvertTo-Json | Set-Content $SettingsFile
        return [PSCustomObject]$DefaultSettings
    }
}

Function Save-Settings {
    param($ConfigObj)
    $ConfigObj | ConvertTo-Json | Set-Content $SettingsFile
}

$Config = Get-Settings

# ==========================================
# 2. XAML GUI DEFINITION
# ==========================================
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="IP Scanner" Height="550" Width="850" WindowStartupLocation="CenterScreen">
    <Window.Resources>
        <Style TargetType="Button">
            <Setter Property="Padding" Value="10,5"/>
            <Setter Property="Margin" Value="5"/>
            <Setter Property="Background" Value="#DDDDDD"/>
            <Setter Property="Cursor" Value="Hand"/>
        </Style>
        <Style TargetType="Label">
            <Setter Property="FontWeight" Value="Bold"/>
            <Setter Property="VerticalAlignment" Value="Center"/>
        </Style>
        <Style TargetType="CheckBox">
            <Setter Property="VerticalAlignment" Value="Center"/>
            <Setter Property="Margin" Value="10,0,0,0"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
        </Style>
    </Window.Resources>
    
    <Grid Background="#F0F0F0">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <Border Grid.Row="0" Background="#E0ECF8" BorderBrush="#A0A0A0" BorderThickness="0,0,0,1" Padding="5">
            <StackPanel Orientation="Horizontal">
                <Button Name="btnScan" Content="▶ Scan" FontWeight="Bold" Foreground="Green"/>
                <Button Name="btnStop" Content="⏹ Stop" IsEnabled="False" Foreground="Red"/>
                
                <Label Content="Range:" Margin="10,0,0,0"/>
                <TextBox Name="txtRange" Width="140" VerticalAlignment="Center" Height="22" ToolTip="Format: 192.168.1.1-254"/>
                
                <Label Content="Ports:" Margin="10,0,0,0"/>
                <TextBox Name="txtPorts" Width="160" VerticalAlignment="Center" Height="22" ToolTip="Comma separated (e.g. 80, 443)"/>
            </StackPanel>
        </Border>

        <Border Grid.Row="1" Background="#FFFFFF" Padding="5" Margin="0,0,0,5">
            <StackPanel Orientation="Horizontal">
                <Label Content="Threads:" FontSize="11" Foreground="Gray" FontWeight="Normal"/>
                <TextBox Name="txtLimit" Width="40" VerticalAlignment="Center" Height="20" HorizontalContentAlignment="Center"/>
                
                <CheckBox Name="chkAliveOnly" Content="Show Alive Only"/>
                
                <Button Name="btnSaveSettings" Content="Save Config" FontSize="10" Height="22" Padding="5,0" Margin="20,0,0,0"/>
                <TextBlock Name="lblWarning" Foreground="Red" VerticalAlignment="Center" Margin="10,0,0,0" FontSize="11" FontWeight="Bold"/>
            </StackPanel>
        </Border>

        <DataGrid Name="dgResults" Grid.Row="2" AutoGenerateColumns="False" IsReadOnly="True" 
                  HeadersVisibility="Column" GridLinesVisibility="Horizontal" Background="White" CanUserSortColumns="True">
            <DataGrid.Columns>
                <DataGridTextColumn Header="Status" Binding="{Binding Status}" Width="90"/>
                <DataGridTextColumn Header="IP Address" Binding="{Binding IP}" SortMemberPath="SortIP" Width="120"/>
                <DataGridTextColumn Header="Hostname (DNS)" Binding="{Binding Hostname}" Width="250"/>
                <DataGridTextColumn Header="Open Ports" Binding="{Binding Ports}" Width="*"/>
            </DataGrid.Columns>
            
            <DataGrid.RowStyle>
                <Style TargetType="DataGridRow">
                    <Style.Triggers>
                        <DataTrigger Binding="{Binding Status}" Value="Free">
                            <Setter Property="Foreground" Value="Gray"/>
                            <Setter Property="FontStyle" Value="Italic"/>
                        </DataTrigger>
                        <DataTrigger Binding="{Binding Status}" Value="Alive">
                            <Setter Property="FontWeight" Value="SemiBold"/>
                            <Setter Property="Foreground" Value="Black"/>
                            <Setter Property="Background" Value="#E8F5E9"/>
                        </DataTrigger>
                    </Style.Triggers>
                </Style>
            </DataGrid.RowStyle>
        </DataGrid>

        <StatusBar Grid.Row="3">
            <StatusBarItem>
                <TextBlock Name="lblStatus" Text="Ready"/>
            </StatusBarItem>
            <StatusBarItem HorizontalAlignment="Right">
                <ProgressBar Name="pbProgress" Width="150" Height="15"/>
            </StatusBarItem>
        </StatusBar>
    </Grid>
</Window>
"@

# ==========================================
# 3. HELPER FUNCTIONS
# ==========================================

Function Get-IPList {
    param($RangeString)
    $IPs = @()
    try {
        if ($RangeString -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})') {
            $Base = $matches[1]
            $Start = [int]$matches[2]
            $End = [int]$matches[3]
            if ($Start -le $End) {
                $Start..$End | ForEach-Object { $IPs += "$Base$_" }
            }
        } 
        elseif ($RangeString -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
             $IPs += $RangeString
        }
    } catch { }
    return $IPs
}

# ==========================================
# 4. GUI LOGIC
# ==========================================
$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)

# Connect Controls
$btnScan = $window.FindName("btnScan")
$btnStop = $window.FindName("btnStop")
$btnSaveSettings = $window.FindName("btnSaveSettings")
$txtRange = $window.FindName("txtRange")
$txtPorts = $window.FindName("txtPorts")
$txtLimit = $window.FindName("txtLimit")
$dgResults = $window.FindName("dgResults")
$lblStatus = $window.FindName("lblStatus")
$pbProgress = $window.FindName("pbProgress")
$lblWarning = $window.FindName("lblWarning")
$chkAliveOnly = $window.FindName("chkAliveOnly")

# Data Binding
# $MasterList holds ALL data. $ResultsList is what is shown on screen.
$MasterList = New-Object System.Collections.Generic.List[Object] 
$ResultsList = New-Object System.Collections.ObjectModel.ObservableCollection[Object]
$dgResults.ItemsSource = $ResultsList

# Load UI Values
$txtRange.Text = $Config.LastRange
$txtPorts.Text = $Config.PortsToScan
$txtLimit.Text = $Config.ThreadLimit

# -- Save Settings Button --
$btnSaveSettings.Add_Click({
    $Config.ThreadLimit = $txtLimit.Text
    $Config.PortsToScan = $txtPorts.Text
    $Config.LastRange = $txtRange.Text
    Save-Settings -ConfigObj $Config
    [System.Windows.MessageBox]::Show("Settings saved to scanner_settings.json", "Saved")
})

# -- Filter Logic (Checkbox) --
$chkAliveOnly.Add_Click({
    $ResultsList.Clear()
    if ($chkAliveOnly.IsChecked) {
        # Show only Alive
        $MasterList | Where-Object { $_.Status -eq "Alive" } | ForEach-Object { $ResultsList.Add($_) }
    } else {
        # Show All
        $MasterList | ForEach-Object { $ResultsList.Add($_) }
    }
})

# Global Variables
$Global:RunspacePool = $null
$Global:Jobs = @()
$script:scanTimer = $null

$btnScan.Add_Click({
    $Range = $txtRange.Text
    $ThreadMax = [int]$txtLimit.Text
    $TargetPorts = $txtPorts.Text -split ',' | ForEach-Object { $_.Trim() }

    $IPList = Get-IPList -RangeString $Range
    if ($IPList.Count -eq 0) { $lblWarning.Text = "Invalid Range Format"; return }
    $lblWarning.Text = ""

    # Auto-Save
    $Config.LastRange = $Range; $Config.PortsToScan = $txtPorts.Text; $Config.ThreadLimit = $txtLimit.Text
    Save-Settings -ConfigObj $Config

    # Reset UI
    $MasterList.Clear()
    $ResultsList.Clear()
    $btnScan.IsEnabled = $false
    $btnStop.IsEnabled = $true
    $pbProgress.Value = 0
    $pbProgress.Maximum = $IPList.Count
    $lblStatus.Text = "Scanning $($IPList.Count) IPs..."

    # Create Thread Pool
    if ($Global:RunspacePool) { $Global:RunspacePool.Dispose() }
    $Global:RunspacePool = [runspacefactory]::CreateRunspacePool(1, $ThreadMax)
    $Global:RunspacePool.Open()

    $Global:Jobs = @()
    foreach ($IP in $IPList) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $Global:RunspacePool
        
        $ps.AddScript({
            param($TargetIP, $Ports)
            
            # --- SORTING LOGIC ---
            # Converts 192.168.1.5 -> "192.168.001.005" for correct sorting
            $parts = $TargetIP -split '\.'
            $sKey = "{0:D3}.{1:D3}.{2:D3}.{3:D3}" -f [int]$parts[0], [int]$parts[1], [int]$parts[2], [int]$parts[3]

            $ResultObj = New-Object PSObject -Property @{
                IP = $TargetIP
                SortIP = $sKey    # Hidden column used for sorting
                Status = "Free"
                Hostname = ""
                Ports = ""
            }

            $Ping = New-Object System.Net.NetworkInformation.Ping
            try {
                $Reply = $Ping.Send($TargetIP, 250)
                if ($Reply.Status -eq "Success") {
                    $ResultObj.Status = "Alive"
                    try { $ResultObj.Hostname = [System.Net.Dns]::GetHostEntry($TargetIP).HostName } catch {}

                    # Port Scan
                    $OpenPorts = @()
                    foreach ($P in $Ports) {
                        if ([string]::IsNullOrWhiteSpace($P)) { continue }
                        try {
                            $socket = New-Object System.Net.Sockets.TcpClient
                            $connect = $socket.BeginConnect($TargetIP, [int]$P, $null, $null)
                            if ($connect.AsyncWaitHandle.WaitOne(100, $false)) {
                                if ($socket.Connected) {
                                    $OpenPorts += $P
                                    $socket.EndConnect($connect)
                                }
                            }
                            $socket.Close(); $socket.Dispose()
                        } catch {}
                    }
                    $ResultObj.Ports = ($OpenPorts -join ", ")
                }
            } catch {}
            return $ResultObj
        }) | Out-Null
        
        $ps.AddArgument($IP)
        $ps.AddArgument($TargetPorts)
        
        $job = New-Object PSObject -Property @{ Pipe = $ps; ResultHandle = $ps.BeginInvoke() }
        $Global:Jobs += $job
    }

    # Timer for Results
    if ($script:scanTimer) { $script:scanTimer.Stop() }
    $script:scanTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:scanTimer.Interval = [TimeSpan]::FromMilliseconds(200)
    
    $script:scanTimer.Add_Tick({
        $Pending = 0
        foreach ($job in $Global:Jobs) {
            if ($job.Pipe -ne $null) {
                if ($job.Pipe.InvocationStateInfo.State -eq 'Completed') {
                    $res = $job.Pipe.EndInvoke($job.ResultHandle)
                    $job.Pipe.Dispose()
                    $job.Pipe = $null
                    
                    if ($res) {
                        $item = $res[0]
                        # 1. Add to Master List (Memory)
                        $MasterList.Add($item)
                        
                        # 2. Add to Display List (Visual) - Respecting the Checkbox
                        if ($chkAliveOnly.IsChecked) {
                            if ($item.Status -eq "Alive") { $ResultsList.Add($item) }
                        } else {
                            $ResultsList.Add($item)
                        }
                        
                        $pbProgress.Value += 1
                    }
                } else {
                    $Pending++
                }
            }
        }
        
        if ($Pending -eq 0) {
            $this.Stop()
            $btnScan.IsEnabled = $true
            $btnStop.IsEnabled = $false
            $lblStatus.Text = "Scan Complete."
            if ($Global:RunspacePool) { $Global:RunspacePool.Dispose() }
        }
    })
    $script:scanTimer.Start()
})

# -- Stop Logic --
$btnStop.Add_Click({
    if ($script:scanTimer) { $script:scanTimer.Stop() }
    foreach ($j in $Global:Jobs) {
        if ($j.Pipe) { try { $j.Pipe.Stop(); $j.Pipe.Dispose() } catch {} }
    }
    if ($Global:RunspacePool) { $Global:RunspacePool.Dispose() }
    $lblStatus.Text = "Stopped."
    $btnScan.IsEnabled = $true; $btnStop.IsEnabled = $false
})

$window.ShowDialog() | Out-Null
