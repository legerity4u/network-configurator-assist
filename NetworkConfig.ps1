param (
    [switch]$Help,
    [string]$EncryptedFilePath,
    [switch]$SilentMode
)

# Check for the Help switch first
if ($Help) {
    Write-Host "This script is used to automatically configure a wired network adapter" -ForegroundColor Yellow
    Write-Host "to work either on a DHCP network or on a network with static parameters." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Usage: .\NetworkConfig.ps1 -EncryptedFilePath <path_to_encrypted_file> [-Help] [-SilentMode]" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "Parameters:"
    Write-Host "  -EncryptedFilePath <path_to_encrypted_file>: Specify the path where encrypted network config is located. (Mandatory)"
    Write-Host "  -SilentMode: Suppress log output to console. (Optional)"
    Write-Host "  -Help: Display this help message. (Optional)"
    exit
}

# Check for admin privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as Administrator." -ForegroundColor Red
    exit
}

# Resolve paths
try { 
    $EncryptedFilePath = Resolve-Path $EncryptedFilePath 
} catch {
    Write-Host "Encrypted configuration file not found: $EncryptedFilePath" -ForegroundColor Red
    exit
}

$LogFilePath = Join-Path $PSScriptRoot ".netconf.log"
Write-Host "See Log file: $LogFilePath"

# Logging function
function Write-Log {
    param ([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    try {
        Add-Content -Path $LogFilePath -Value "$timestamp - $Message"
    } catch {
        Write-Host "Failed to write to log: $_" -ForegroundColor Red
    }
    if (-not $SilentMode) { Write-Host $Message -ForegroundColor Green }
}

# Decrypt configuration file
function Decrypt-Config {
    param ([string]$EncryptedFilePath)

    if (-not (Test-Path -Path $EncryptedFilePath)) {
        Write-Log "File not found: $EncryptedFilePath"
        return $null
    }

    $decryptionPassword = Read-Host -Prompt "Enter decryption password" -AsSecureString
    $decryptionPlainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($decryptionPassword)
    )

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $decryptionKey = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($decryptionPlainPassword))
    
    try {
        $encryptedContent = Get-Content -Raw -Path $EncryptedFilePath -Encoding UTF8
        if ($decryptionKey.Length -ne 32) { $decryptionKey = $decryptionKey[0..31] }
        $decryptedSecureString = ConvertTo-SecureString -String $encryptedContent -Key $decryptionKey
        $decryptedContent = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($decryptedSecureString)
        )

        try {
            $decryptedJson = $decryptedContent | ConvertFrom-Json
            Write-Log "Decryption successful. JSON structure is valid."
            return $decryptedJson
        } catch {
            Write-Log "Decrypted file is not valid JSON."
            return $null
        }
    } catch {
        Write-Log "Error decrypting file: $_"
        return $null
    }
}

# Normalize MAC address
function Normalize-MacAddress {
    param ([string]$MacAddress)
    return ($MacAddress -replace '[-]', ':').ToUpper().Trim()
}

# Disable other adapters
function Disable-OtherAdapters {
    param ([string]$KeepInterfaceName)
    Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Name -ne $KeepInterfaceName } | ForEach-Object {
        Write-Log "Disabling adapter: $($_.Name)"
        Disable-NetAdapter -Name $_.Name -Confirm:$false
    }
}

# Enable disabled adapters
function Enable-DisabledAdapters {
    Get-NetAdapter | Where-Object { $_.Status -eq "Disabled" } | ForEach-Object {
        Write-Log "Enabling adapter: $($_.Name)"
        Enable-NetAdapter -Name $_.Name -Confirm:$false
    }
}

# Test internet connection
function Test-InternetConnection {
    param ([string]$InterfaceName)
    $IPAddress = (Get-NetIPAddress -InterfaceAlias $InterfaceName -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress -ErrorAction SilentlyContinue)
    Write-Log "Adapter $InterfaceName has IP: $IPAddress"
    if (-not $IPAddress -or $IPAddress -like "169.*") {
        Write-Log "No valid IP on interface $InterfaceName."
        return $false
    }
    try {
        if (Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet) {
            Write-Log "Internet connection established via $IPAddress"
            return $true
        } else {
            Write-Log "No internet connection via $IPAddress"
            return $false
        }
    } catch {
        Write-Log "Error testing internet connection: $_"
        return $false
    }
}

# Remove existing IPs and gateways
function Clear-NetworkConfig {
    param ([string]$AdapterName)

    try {
        Get-NetIPAddress -InterfaceAlias $AdapterName -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Log "Removing IP: $($_.IPAddress) from $AdapterName"
            Remove-NetIPAddress -InterfaceAlias $AdapterName -IPAddress $_.IPAddress -Confirm:$false -ErrorAction SilentlyContinue
        }
        Get-NetIPConfiguration -InterfaceAlias $AdapterName | Select-Object -ExpandProperty IPv4DefaultGateway | ForEach-Object {
            Write-Log "Removing gateway: $($_.NextHop) from $AdapterName"
            Remove-NetRoute -InterfaceAlias $AdapterName -NextHop $_.NextHop -Confirm:$false -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Log "Error clearing network configuration: $_"
    }
}

# Configure static IP
function Configure-StaticIP {
    param ([string]$AdapterName, [string]$FixedIP, [int]$PrefixLength, [string]$Gateway, [array]$DnsServers, [array]$WinsServers)
    Clear-NetworkConfig -AdapterName $AdapterName
    # Set new IP address and gateway
    Write-Log "Configuring static IP: $FixedIP/$PrefixLength, Gateway: $Gateway for $AdapterName."
    New-NetIPAddress -InterfaceAlias $AdapterName -IPAddress $FixedIP -PrefixLength $PrefixLength -DefaultGateway $Gateway -Confirm:$false | Out-Null
    # Configure DNS servers
    Write-Log "Configuring for $AdapterName DNS servers: $($DnsServers -join ', ')."
    Set-DnsClientServerAddress -InterfaceAlias $AdapterName -ServerAddresses $DnsServers -Confirm:$false | Out-Null
    # Configure WINS servers
    Write-Log "Configuring for $AdapterName WINS servers: $($WinsServers -join ', ')."
    Set-DnsClient -InterfaceAlias $AdapterName -RegisterThisConnectionsAddress $true
    # Use WMI to set WINS server addresses
    $wins = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.Description -eq $AdapterName }
    if ($wins) {
        # Set the WINS server addresses
        $wins.SetWINSServer($WinsServers)
        Write-Log "WINS servers configured successfully."
    } else {
        Write-Log "Failed to find adapter configuration for $AdapterName."
    }
    Write-Log "Static IP and DNS configured for adapter: $AdapterName."
}

# Load configuration
function Initialize-Configuration {
    param ([string]$EncryptedFilePath)

    if (Test-Path $EncryptedFilePath) {
        $decryptedConfig = Decrypt-Config -EncryptedFilePath $EncryptedFilePath
        if (-not $decryptedConfig) {
            Write-Log "Decrypted configuration is empty."
            return $null
        }

        try {
            $decryptedConfig.PrefixLength = [int]$decryptedConfig.PrefixLength
        } catch {
            Write-Log "Invalid PrefixLength value in configuration: $($decryptedConfig.PrefixLength)"
            return $null
        }

        if (-not $decryptedConfig.FixedIP -or -not $decryptedConfig.PrefixLength -or -not $decryptedConfig.Gateway -or -not $decryptedConfig.DnsServers -or -not $decryptedConfig.WinsServers) {
            Write-Log "Missing required configuration parameters in decrypted file."
            return $null
        }

        return $decryptedConfig
    } else {
        Write-Log "Configuration file not found: '$EncryptedFilePath'"
        return $null
    }
}

# Main script execution
$Adapters = Get-NetAdapter | Where-Object { $_.MediaType -eq "802.3" -and $_.Status -eq "Up" }
if ($Adapters.Count -eq 0) {
    Write-Log "No wired adapters available."
    exit
} elseif ($Adapters.Count -eq 1) {
    $SelectedAdapter = $Adapters[0]
} else {
    Write-Log "Available adapters:"
    for ($i = 0; $i -lt $Adapters.Count; $i++) { Write-Log "$($i + 1): $($Adapters[$i].Name)" }
    do {
        $selection = Read-Host "Select adapter number (1-$($Adapters.Count))"
    } while (-not ($selection -as [int]) -or $selection -lt 1 -or $selection -gt $Adapters.Count)
    $SelectedAdapter = $Adapters[$selection - 1]
}

$AdapterName = $SelectedAdapter.Name
Write-Log "Selected adapter: $AdapterName"
Disable-OtherAdapters -KeepInterfaceName $AdapterName

if (-not (Test-InternetConnection -InterfaceName $AdapterName)) {
    Write-Log "No internet connection. Trying DHCP configuration..."
    Clear-NetworkConfig -AdapterName $AdapterName
    Set-NetIPInterface -InterfaceAlias $AdapterName -Dhcp Enabled -Confirm:$false
    Restart-NetAdapter -Name $AdapterName
    Write-Log "Wait 10 seconds for applying parameters."
    Start-Sleep -Seconds 15
    if (-not (Test-InternetConnection -InterfaceName $AdapterName)) {
        Write-Log "DHCP configuration failed. Switching to static IP..."
        $config = Initialize-Configuration -EncryptedFilePath $EncryptedFilePath
        if (-not $config) { exit }
        Write-Log "Loaded configuration: \n $($config | ConvertTo-Json -Depth 10)"
        Configure-StaticIP -AdapterName $AdapterName -FixedIP $config.FixedIP -PrefixLength $config.PrefixLength -Gateway $config.Gateway -DnsServers $config.DnsServers -WinsServers $config.WinsServers
        Restart-NetAdapter -Name $AdapterName
        Write-Log "Wait 10 seconds for applying parameters."
        Start-Sleep -Seconds 10 # Waiting for changing AddressState from Tentaitive to Preffered
    }
}
# Checking IP status
$currentIPs = Get-NetIPAddress -InterfaceAlias $AdapterName -AddressFamily IPv4
foreach ($ip in $currentIPs) {
    if ($ip.AddressState -eq "Preferred") {
        Write-Log "IP address $($ip.IPAddress) is active and preferred on adapter $AdapterName."
    } else {
        Write-Log "IP address $($ip.IPAddress) is in state: $($ip.AddressState)."
    }
}
Enable-DisabledAdapters
Write-Log "Network configuration completed."