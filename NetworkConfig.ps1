#Requires -RunAsAdministrator
param (
    [switch]$Help,
    [string]$EncryptedFilePath
)
Write-Host "`n`nThis script is used to automatically configure a wired network adapter" -ForegroundColor Green
Write-Host "to work either on a DHCP network or on a network with static parameters." -ForegroundColor Green

# Check for the Help switch first
if ($Help) {
    Write-Host "`n`nUsage: " -ForegroundColor Green
    Write-Host "`t.\NetworkConfig.ps1 -EncryptedFilePath " -ForegroundColor DarkYellow -NoNewLine
    Write-Host "<path_to_encrypted_file>" -ForegroundColor Blue -NoNewline
    Write-Host "  [-Help]" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "Parameters:" -ForegroundColor Green
    Write-Host " `t-EncryptedFilePath <path_to_encrypted_file> " -ForegroundColor DarkCyan -NoNewline
    Write-Host "`t:   Specify the path where encrypted network for static configuration is located. (" -ForegroundColor Gray -NoNewline
    Write-Host "Mandatory" -ForegroundColor DarkYellow -NoNewline
    Write-Host ")" -ForegroundColor Gray
    Write-Host " `t-Help" -ForegroundColor DarkCyan -NoNewline
    Write-Host "`t: Display this help message. (" -ForegroundColor Gray -NoNewline
    Write-Host "Optional"  -ForegroundColor DarkYellow -NoNewline
    Write-Host ")`n`n" -ForegroundColor Gray
    exit
}

# Resolve paths
try { 
    $EncryptedFilePath = Resolve-Path $EncryptedFilePath 
} catch {
    Write-Host "Encrypted configuration file not found: $EncryptedFilePath" -ForegroundColor Red
    exit 1
}


$LogFilePath = Join-Path $PSScriptRoot ".netconf.log"
Write-Host "See Log file: " -NoNewLine
Write-Host "$LogFilePath" -ForegroundColor Cyan

# Logging function
function Write-Log {
    param (
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR")][string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$Level] $Message"
    Add-Content -Path $LogFilePath -Value $logEntry
    $color = if ($Level -eq "INFO") { "Green" } elseif ($Level -eq "WARN") { "Yellow" } else { "Red" }
    Write-Host $logEntry -ForegroundColor $color
}

# Read and decrypt configuration file wiyj static params for IPv4
function Read-Config {
    param ([string]$EncryptedFilePath)

    if (-not (Test-Path -Path $EncryptedFilePath)) {
        Write-Log "File not found: $EncryptedFilePath" "ERROR"
        return $null
    }
    $maxAttempts = 3
    $attempts = 0
    $decryptedContent = $null
    while ($attempts -lt $maxAttempts) {
        # Request the password from the user
        $decryptionPassword = Read-Host -Prompt "Enter decryption password:   " -AsSecureString
        $decryptionPlainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($decryptionPassword)
        )

        # Password generation
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $decryptionKey = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($decryptionPlainPassword))

        try {
            # Reading encrypted contents
            $encryptedContent = Get-Content -Raw -Path $EncryptedFilePath -Encoding UTF8

            # We will make sure that the key length is 32 bytes
            if ($decryptionKey.Length -ne 32) { 
                $decryptionKey = $decryptionKey[0..31] 
            }

            # Trying to decrypt with suppression of systemic errors
            $ErrorActionPreference = "Stop"  # We will make sure that errors become terminal
            try {
                $decryptedSecureString = ConvertTo-SecureString -String $encryptedContent -Key $decryptionKey -ErrorAction Stop
                $decryptedContent = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($decryptedSecureString)
                )

                # We check whether the decrypted contents are correct json
                try {
                    $decryptedJson = $decryptedContent | ConvertFrom-Json
                    Write-Log "Decryption successful. JSON structure is valid." "INFO"
                    return $decryptedJson
                } catch {
                    Write-Log "Decrypted file is not valid JSON." "ERROR"
                    return $null
                }
            } catch {
                # Error processing during decoding
                Write-Log "Incorrect password or corrupted file. Please try again." "ERROR"
                $attempts++
                if ($attempts -eq $maxAttempts) {
                    Write-Log "Maximum attempts reached. Exiting." "ERROR"
                    return $null
                }
            }
        } catch {
            Write-Log "Error reading the encrypted file: $_" "ERROR"
            return $null
        }
    }
}

# Test internet connection
function Test-InternetConnection {
    param ([int]$InterfaceId)
    
    # Get adapter by InterfaceId
    $adapter = Get-NetAdapter | Where-Object { $_.InterfaceIndex -eq $InterfaceId }
    if ($null -eq $adapter) {
        return $false
    }
    
    # Check adapter status
    if ($adapter.Status -eq "Up" -and $adapter.MediaConnectionState -eq "Connected") {
        # Ckeck IP-address
        $sourceAddress = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $InterfaceId
        if ($sourceAddress.IPAddress -like "169.254.*") {
            Write-Log "[Test-InternetConnection] sourceAddress was selfassigned = '$($sourceAddress.IPAddress)'" "WARN"
            return $false
        }
        
        # Ping check for network interface
        $result = ping -S $sourceAddress.IPAddress -4 -n 1 -w 10 google.com
        if ($result -match "TTL=") {
            return $true
        } else {
            return $false
        }
    } else {
        return $false
    }
}

# Function for converting the prefix length into the subnet mask
function ConvertTo-SubnetMask {
    param (
        [Parameter(Mandatory = $true)]
        [int]$PrefixLength
    )

    # Checking the validity of the length of the prefix
    if ($PrefixLength -lt 0 -or $PrefixLength -gt 32) {
        throw "The value of the prefix should be from 0 to 32."
    }

    # Create a subnet mask
    $mask = [uint32]::MaxValue -shl (32 - $PrefixLength)

    # We convert the result into a string of IP address format
    $octets = @()
    for ($i = 24; $i -ge 0; $i -= 8) {
        $octet = ($mask -shr $i) -band 255
        $octets += $octet
    }

    # Return the subnet mask in IP address format
    return "$($octets[0]).$($octets[1]).$($octets[2]).$($octets[3])"
}

function Get-MediaState {
    param (
        [int]$InterfaceIndex
    )

    $adapter = Get-CimInstance -Class Win32_NetworkAdapter -Filter "InterfaceIndex = $InterfaceIndex"
    
    if ($adapter.NetConnectionStatus -eq 1) {
        Write-Log "The adapter is connecting. Waiting for 10 seconds..." "INFO"
        Start-Sleep -Seconds 10
        $adapter = Get-CimInstance -Class Win32_NetworkAdapter -Filter "InterfaceIndex = $InterfaceIndex"
    }

    if ($adapter.NetConnectionStatus -eq 2) {
        return "Media connected"
    } elseif ($adapter.NetConnectionStatus -eq 0 -or $adapter.NetConnectionStatus -eq 7) {
        return "Media disconnected"
    } else {
        return "Unknown"
    }
}
# Function for output of the properties of a network adapter
function Get-NetworkAdapterProperties {
    param (
        [int]$InterfaceId
    )
    $result = ""
    # Get adapter by InterfaceId
    $adapter = Get-NetAdapter | Where-Object {$_.InterfaceIndex -eq $InterfaceId}
    if ($null -eq $adapter) {
        $result += "Adapter with the specified Interfaceid was not found.`n"
        return $result
    }
    # Get adapter description
    $result += "Ethernet adapter '$($adapter.Name)':`n"
    # Get the state of connection with the network
    $mediaState = Get-MediaState -InterfaceIndex $InterfaceId
    $result += "   Media State . . . . . . . . . . . : $mediaState`n"
    $result += "   Description . . . . . . . . . . . : $($adapter.InterfaceDescription)`n"
    $result += "   Physical Address. . . . . . . . . : $($adapter.MacAddress)`n"
    # Get Connection-specific DNS Suffix
    $wmiAdapter = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "InterfaceIndex = $InterfaceId"
    if ($wmiAdapter) {
        $dnsSuffixes = $wmiAdapter.DNSDomainSuffixSearchOrder
        $result += "   Connection-specific DNS Suffix  . : $($dnsSuffixes -join ', ')`n"
        # Get IP-address
        if ($wmiAdapter.DHCPEnabled) {
            $result += "   DHCP Enabled. . . . . . . . . . . : Yes`n"
            $result += "   Autoconfiguration Enabled . . . . : Yes`n"
        } else {
            $result += "   DHCP Enabled. . . . . . . . . . . : No`n"
            $result += "   Autoconfiguration Enabled . . . . : No`n"
        }
    }
    # Check if the adapter is connected
    if ($mediaState -eq "Media connected") {
        # Get IP address and subnet mask
        $ipConfig = Get-NetIPConfiguration -InterfaceIndex $InterfaceId
        $ipv4Addresses = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $InterfaceId
        foreach ($address in $ipv4Addresses) {
            if ($address.PrefixOrigin -eq "Dhcp") {
                $result += "   IPv4 Address. . . . . . . . . . . : $($address.IPAddress) (Preferred)`n"
                $result += "   Subnet Mask . . . . . . . . . . . : $(ConvertTo-SubnetMask -PrefixLength $address.PrefixLength)`n"
                if ($wmiAdapter) {
                    $leaseObtained = $wmiAdapter.DHCPLeaseObtained
                    $leaseExpires = $wmiAdapter.DHCPLeaseExpires
                    $leaseExpiresDateTime = [Management.ManagementDateTimeConverter]::ToDateTime($leaseExpires)
                    $leaseObtainedDateTime = [Management.ManagementDateTimeConverter]::ToDateTime($leaseObtained)
                    $result += "   Lease Expires . . . . . . . . . . : $($leaseExpiresDateTime.ToString('f'))`n"#.ToString('D')) $($leaseExpires.ToString('T'))`n"
                    $result += "   Lease Obtained. . . . . . . . . . : $($leaseObtainedDateTime.ToString('f'))`n"#.ToString('D')) $($leaseObtained.ToString('T'))`n"
                    $result += "   DHCP Server . . . . . . . . . . . : $($wmiAdapter.DHCPServer)`n"
                }
            } elseif ($address.PrefixOrigin -eq "Manual") {
                $result += "   IPv4 Address. . . . . . . . . . . : $($address.IPAddress)`n"
                $result += "   Subnet Mask . . . . . . . . . . . : $(ConvertTo-SubnetMask -PrefixLength $address.PrefixLength)`n"
            }
        }
        # Get default gateway
        if ($ipConfig.IPv4DefaultGateway.NextHop) {
            $result += "   Default Gateway . . . . . . . . . : $($ipConfig.IPv4DefaultGateway.NextHop)`n"
        }
        # Get DNS servers
        $dnsServers = Get-DnsClientServerAddress -InterfaceIndex $InterfaceId -AddressFamily IPv4
        if ($dnsServers) {
            $allDnsServers = @()
            foreach ($server in $dnsServers) {
                $allDnsServers += $server.ServerAddresses
            }
            if ($allDnsServers.Count -gt 0) {
                $result += "   DNS Servers . . . . . . . . . . . : $($allDnsServers[0])`n"
                for ($i = 1; $i -lt $allDnsServers.Count; $i++) {
                    $result += "                                       $($allDnsServers[$i])`n"
                }
            } else {$result += "   DNS Servers . . . . . . . . . . . : None`n"}
        } else {$result += "   DNS Servers . . . . . . . . . . . : None`n"}
        # Get WINS servers
        if ($wmiAdapter) {
            $winsOutput = netsh interface ipv4 show wins name="$($adapter.Name)"
            $winsLines = $winsOutput | Where-Object {$_ -match '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'}
            if ($winsLines) {
                $winsArray = @()
                foreach ($line in $winsLines) {
                    $ipAddress = ($line -replace '.*: ', '').Trim()
                    $winsArray += $ipAddress
                }
                # Get primary WINS server
                $result += "   Primary WINS Server . . . . . . . : $($winsArray[0])`n"
                # Get secondary WINS servers
                if ($winsArray.Count -gt 1) {
                    $result += "   Secondary WINS Server . . . . . . : $($winsArray[1])`n"
                    for ($i = 2; $i -lt $winsArray.Count; $i++) {
                        $result += "                                       $($winsArray[$i])`n"
                    }
                } else {
                    $result += "   Secondary WINS Server . . . . . . : None`n"
                }
            } else {
                $result += "   Primary WINS Server . . . . . . . : None`n"
                $result += "   Secondary WINS Server . . . . . . : None`n"
            }
        }
        # Get NetBIOS over Tcpip
        if ($wmiAdapter) {
            $netbiosStatus = $wmiAdapter.TcpipNetbiosOptions
            if ($netbiosStatus -eq 0) {
                $result += "   NetBIOS over Tcpip. . . . . . . . : Enabled via DHCP`n"
            } elseif ($netbiosStatus -eq 1) {
                $result += "   NetBIOS over Tcpip. . . . . . . . : Enabled`n"
            } elseif ($netbiosStatus -eq 2) {
                $result += "   NetBIOS over Tcpip. . . . . . . . : Disabled`n"
            }
        }
    }
    return $result
}

# Remove existing IPs and gateways
function Clear-NetworkConfig {
    param ([int]$InterfaceId)
    
    # Get adapter name by Interface Id
    $adapter = Get-NetAdapter | Where-Object {$_.InterfaceIndex -eq $InterfaceId}
    if ($null -eq $adapter) {
        Write-Log "[Clear-NetworkConfig] Adapter with InterfaceId ='$InterfaceId' was not found." "ERROR"
        return $false
    }

    # Disconnect DHCP if it is turned on
    Set-NetIPInterface -InterfaceIndex $InterfaceId -Dhcp Disabled

    # Check the condition of DHCP
    $dhcpStatus = Get-NetIPInterface -InterfaceIndex $InterfaceId | Select-Object Dhcp
    Write-Log "DHCP condition for the interface $InterfaceId = $($dhcpStatus.Dhcp)" "INFO"

    # Remove IP address and gateways
    $existingIpAddresses = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $InterfaceId
    foreach ($ip in $existingIpAddresses) {
        Remove-NetIPAddress -InterfaceIndex $InterfaceId -IPAddress $ip.IPAddress -Confirm:$false
        Write-Log "The existing IP address is removed: $($ip.IPAddress)" "INFO"
    }

    # Remove routes from the network configuration
    Get-NetIPConfiguration -InterfaceIndex $InterfaceId | Select-Object -ExpandProperty IPv4DefaultGateway | ForEach-Object {
        Remove-NetRoute -InterfaceIndex $InterfaceId -NextHop $_.NextHop -DestinationPrefix 0.0.0.0/0 -Confirm:$false -ErrorAction SilentlyContinue
    }

    # Reset DNS servers for using DHCP
    Set-DnsClientServerAddress -InterfaceIndex $InterfaceId -ResetServerAddresses
    
    # Reset WINS servers for using DHCP
    netsh interface ipv4 set wins name="$($adapter.Name)" source=dhcp
    
    # Reset NetBIOS over TCP/IP
    if (Set-NetBiosOptions -InterfaceId $InterfaceId -NBTOption 0) {
        Write-Log "TcpipNetbiosOptions was successfully set to Default (0)" "INFO"
    } else {
        Write-Log "Failed to set TcpipNetbiosOptions to Default (0)" "ERROR"
    }

    # Reset DNS-suffixes
    $arguments = @{DNSDomainSuffixSearchOrder = @("")}  # Empty array for reset this parameter

    $result = Invoke-CimMethod -ClassName Win32_NetworkAdapterConfiguration -MethodName "SetDNSSuffixSearchOrder" -Arguments $arguments
    if ($result.ReturnValue -eq 0) {
        Write-Log "DNSSuffixSearchOrder was successfully reset." "INFO"
    } else {
        Write-Log "Failed to reset DNSSuffixSearchOrder. Return value: $($result.ReturnValue)" "ERROR"
    }


    return $true
}

# Setup NetBIOS over TCP/IP
function Set-NetBiosOptions {
    param (
        [int]$InterfaceId,
        [int]$NBTOption
    )

    # We get information about the network adapter
    $adapter = Get-NetAdapter -InterfaceIndex $InterfaceId
    if ($adapter) {
        # The path to the Netbios setup registry
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$($adapter.InterfaceGuid)"
        
        # We check if there is a way to the registry
        if (Test-Path $registryPath) {
            # We get the current value of Netbios
            $currentValue = Get-NetBiosOptions -InterfaceId $InterfaceId
            
            # If the current value does not coincide with the new value, we update it
            if ($currentValue -ne $NBTOption) {
                try {
                    Set-ItemProperty -Path $registryPath -Name "NetbiosOptions" -Value $NBTOption #-Verbose
                    
                    # We check the new meaning
                    $newValue = Get-NetBiosOptions -InterfaceId $InterfaceId
                    if ($newValue -eq $NBTOption) {
                        return $true
                    } else {
                        return $false
                    }
                } catch {
                    return $false
                }
            } else {
                return $true
            }
        } else {
            return $false
        }
    } else {
        Write-Log "Network adapter with InterfaceIndex $InterfaceId not found." "ERROR"
        return $false
    }
}


# Get NetBIOS over TCP/IP value from registry
function Get-NetBiosOptions {
    param (
        [int]$InterfaceId
    )

    # We get information about the network adapter
    $adapter = Get-NetAdapter -InterfaceIndex $InterfaceId
    if ($adapter) {
        # The path to the Netbios setup registry
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$($adapter.InterfaceGuid)"
        
        # We check if there is a way to the registry
        if (Test-Path $registryPath) {
            # Set the value of TCPIPNETBIOSOPTIONS (0 -by default, 1 -turn on, 2 -turn off)
            $propertyName = "NetbiosOptions"
            try {
                $currentValue = (Get-ItemProperty -Path $registryPath -Name $propertyName).$propertyName
                return $currentValue
            } catch {
                Write-Log "Error when obtaining property value '$propertyName': $_" "ERROR"
                return $null
            }
        } else {
            Write-Log "The path to the registry'$registryPath' does not exist." "ERROR"
            return $null
        }
    } else {
        Write-Log "Network adapter with InterfaceIndex $InterfaceId was not found." "ERROR"
        return $null
    }
}

# Configure static IP
function Set-StaticIP {
    param (
        [int]$IfaceId,
        [string]$FixedIP,
        [int]$PrefixLength,
        [string]$Gateway,
        [array]$DnsServers,
        [array]$WinsServers,
        [array]$DnsSuffixes
    )
    # Check if there is an adapter with the specified InterfaceId
    $adapter = Get-NetAdapter | Where-Object {$_.InterfaceIndex -eq $IfaceId}
    if ($null -eq $adapter) {
        Write-Log "[Set-StaticIP] Adapter with the specified $iFaceid was not found. $($Error[0].Message)" "ERROR"
        return $false
    }
    # Apply a static IP address
    $ipParams = @{
        InterfaceIndex = $IfaceId
        IPAddress = $FixedIP
        PrefixLength = $PrefixLength
        AddressFamily = "IPv4"
        DefaultGateway = $Gateway
    }
    New-NetIPAddress @ipParams
    Write-Log "[Set-StaticIP] Static parameters are used." "INFO"
    # Setup DNS-servers
    if ($DnsServers.Count -gt 0) {
        Set-DnsClientServerAddress -InterfaceIndex $IfaceId -ServerAddresses $DnsServers
        Write-Log "DNS servers $($DnsServers -join ', ') was applyed for adapter '$($adapter.Name)'" "INFO"
    }

    # Setup WINS-servers
    try {
        netsh interface ipv4 set winsservers name="$($adapter.Name)" source=static
        foreach ($winsServer in $WinsServers) {
            netsh interface ipv4 add winsservers name="$($adapter.Name)" address="$winsServer"
        }
        Write-Log "WINS servers $($WinsServers -join ', ') was applied for adapter '$($adapter.Name)'" "INFO"
    } catch {
        Write-Log "Error when setting up WINS servers: $($Error[0].Message)" "ERROR"
    }

    # Setup NetBIOS over TCP/IP
    if (Set-NetBiosOptions -InterfaceId $InterfaceId -NBTOption 1) {
        Write-Log "TcpipNetbiosOptions was successfully set to Enabled (1)" "INFO"
    } else {
        Write-Log "Failed to set TcpipNetbiosOptions to Enabled (1)" "ERROR"
    }

    #$wmiAdapter = Get-CimInstance -Class Win32_NetworkAdapterConfiguration -Filter "InterfaceIndex = $InterfaceId"
    # Setup DNS-suffixes
    if ($DnsSuffixes) {
        $result = Invoke-CimMethod -ClassName win32_networkadapterconfiguration -MethodName "SetDNSSuffixSearchOrder" -Arguments @{DNSDomainSuffixSearchOrder=$DnsSuffixes}
        if ($result.ReturnValue -eq 0) {
            Write-Log "DNSSuffixSearchOrder was successfully set $($DnsSuffixes -join ', ')" "INFO"
        } else {
            Write-Log "Failed to set DNSSuffixSearchOrder. Return value: $($result.ReturnValue)" "ERROR"
        }
    }
    return $true
}

# Load configuration
function Initialize-Configuration {
    param ([string]$EncryptedFilePath)
    if (Test-Path $EncryptedFilePath) {
        $decryptedConfig = Read-Config -EncryptedFilePath $EncryptedFilePath
        if (-not $decryptedConfig) {
            Write-Log "Decrypting configuration was failed." "ERROR"
            return $null
        }
        try {
            $decryptedConfig.PrefixLength = [int]$decryptedConfig.PrefixLength
        } catch {
            Write-Log "Invalid PrefixLength value in configuration: $($decryptedConfig.PrefixLength)"
            return $null
        }
        if (-not $decryptedConfig.FixedIP -or -not $decryptedConfig.PrefixLength -or -not $decryptedConfig.Gateway -or -not $decryptedConfig.DnsServers -or -not $decryptedConfig.WinsServers -or -not $decryptedConfig.DnsSuffixes) {
            Write-Log "Missing required configuration parameters in decrypted file."
            return $null
        }
        return $decryptedConfig
    } else {
        Write-Log "Configuration file not found: '$EncryptedFilePath'"
        return $null
    }
}

# Check available network adapters
function Select-NetworkAdapter {
    $result = ""
    $Adapters = Get-NetAdapter -Physical | Where-Object { $_.MediaType -eq "802.3"  } # it's may be added if we are not going to configure not connected adapter '-and $_.Status -eq "Up"'
    if ($Adapters.Count -eq 0) {
        Write-Log "No wired adapters available." "ERROR"
        return $null
    } elseif ($Adapters.Count -eq 1) {
        return $Adapters[0]
    } else {
        $result = "Multiple adapters was found. Prompting user for selection.`n"
        for ($i = 0; $i -lt $Adapters.Count; $i++) {
            $result += "      $($i + 1):   $($Adapters[$i].InterfaceDescription)`n"
        }
        Write-Log  $result "INFO"
        do {
            Write-Host "Select adapter number " -NoNewline
            Write-Host "(1-$($Adapters.Count))" -ForegroundColor Yellow -NoNewline
            Write-Host " or type " -NoNewline
            Write-Host "'q'" -ForegroundColor Cyan -NoNewline
            Write-Host " to quit:  " -NoNewline
            $selection = Read-Host
            if ($selection -eq 'q') {
                Write-Log "Administrator terminated the script." "INFO"
                return $null
            }
        } while (-not ($selection -as [int]) -or $selection -lt 1 -or $selection -gt $Adapters.Count)
        return $Adapters[$selection - 1]
    }
}

function Read-Highlight {
    param ([string]$HihglightedWord)
    Write-Host "Do you want to use " -NoNewline
    Write-Host "$HihglightedWord" -ForegroundColor Yellow -NoNewline
    Write-Host " configuration for adapter '" -NoNewLine
    Write-Host "$($SelectedAdapter.Name)" -ForegroundColor Yellow -NoNewLine
    Write-Host "'?   " -NoNewline
    Write-Host " (Yes/No)   " -ForegroundColor White  -NoNewline
    $choice = Read-Host
    return $choice
}
#########################
# Main script execution
#########################
$SelectedAdapter = Select-NetworkAdapter

# Conclusion of information about the selected adapter
if ($null -ne $SelectedAdapter) {
    $InterfaceId = $SelectedAdapter.InterfaceIndex  # Adapter ID for cmd-lets
    # Display and log the adapter settings
    $currentConfiguration = Get-NetworkAdapterProperties -InterfaceId $InterfaceId
    Write-Log $currentConfiguration "INFO"
    $choiceDhcp = Read-Highlight -HihglightedWord "DHCP"
    if ($choiceDhcp -match "(?i)^(n|no)$") {
        Write-Log "Skip reconfiguration for DHCP." "INFO" # The user refused to configure DHCP
        $choiceStatic = Read-Highlight -HihglightedWord "Static"
        if ($choiceStatic -match "(?i)^(n|no)$") {
            Write-Log "Skip reconfiguration for static." "INFO"
        } else {
            # Trying to switch on static configuration
            $config = Initialize-Configuration -EncryptedFilePath $EncryptedFilePath
            if ($config) {
                Write-Log "Loaded configuration: `n $($config | ConvertTo-Json -Depth 10)" "INFO"
                $static = Set-StaticIP -IfaceId $InterfaceId -FixedIP $config.FixedIP -PrefixLength $config.PrefixLength -Gateway $config.Gateway -DnsServers $config.DnsServers -WinsServers $config.WinsServers -DnsSuffixes $config.DnsSuffixes
                if ($null -ne $static) {
                    Write-Log "Static IP was configured for adapter '$($SelectedAdapter.Name)'." "INFO"
                    Write-Log "Waiting 20 seconds for static configuration." "INFO"
                    Restart-NetAdapter -Name $SelectedAdapter.Name
                    Start-Sleep -Seconds 20
                } else {
                    Write-Log "Error configuring static IP." "ERROR"
                }
            } else {
                Write-Log "Error loading configuration for static IP." "ERROR"
            }
        } # Either the user refused statics, or the statics are configured and the adapter was overloaded, or the static tuning error 
    } else { # The user chose DHCP
        Write-Log "Enabling DHCP..." "INFO"
        # Clean previous settings
        if (Clear-NetworkConfig -InterfaceId $InterfaceId) {
            Write-Log "Previous settings IP was cleared." "INFO"
            # Turn on DHCP
            Set-NetIPInterface -InterfaceIndex $InterfaceId -Dhcp Enabled -ManagedAddressConfiguration Enabled -Confirm:$false
            Write-Log "Waiting 20 seconds for applying DHCP configuration." "INFO"
            Restart-NetAdapter -Name $SelectedAdapter.Name
            Start-Sleep -Seconds 20
        } else { # Not successful cleaning of the network parameters on the adapter
            Write-Log "Clear-NetworkConfig was failed." "ERROR"
        } # dhcp or mood, or message about the unsuccessful result, but for the attempts to reconfigure on the adapter you have to restart the script again   
    } # Here the adapter is either configured, but the connection was not tested, or an error of explanation of the reason for the failure of the configuration was issued
    if (Test-InternetConnection -InterfaceId $InterfaceId) {
        Write-Log "Adapter '$($SelectedAdapter.Name)' has Internet access." "INFO"
    } else {        
        Write-Log "No internet connection for '$($SelectedAdapter.Name)'" "WARN"
    }
    # Display and log the new adapter settings
    $currentConfiguration = Get-NetworkAdapterProperties -InterfaceId $InterfaceId
    Write-Log $currentConfiguration "INFO"
}