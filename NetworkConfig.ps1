#Requires -RunAsAdministrator
param (
    [switch]$Help,
    [string]$EncryptedFilePath
)

# Check for the Help switch first
if ($Help) {
    Write-Host "This script is used to automatically configure a wired network adapter" -ForegroundColor Yellow
    Write-Host "to work either on a DHCP network or on a network with static parameters." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Usage: .\NetworkConfig.ps1 -EncryptedFilePath <path_to_encrypted_file> [-Help]" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "Parameters:"
    Write-Host "  -EncryptedFilePath <path_to_encrypted_file>: Specify the path where encrypted network config is located. (Mandatory)"
    Write-Host "  -Help: Display this help message. (Optional)"
    exit
}

# Check for admin privileges
# if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
#     Write-Host "This script must be run as Administrator." -ForegroundColor Red
#     exit 1
# }

# Resolve paths
try { 
    $EncryptedFilePath = Resolve-Path $EncryptedFilePath 
} catch {
    Write-Host "Encrypted configuration file not found: $EncryptedFilePath" -ForegroundColor Red
    exit 1
}
$LogFilePath = Join-Path $PSScriptRoot ".netconf.log"
Write-Host "See Log file: $LogFilePath"

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

# Test internet connection
function Test-InternetConnection {
    param ([int]$InterfaceId)
    
    # Get adapter by InterfaceId
    $adapter = Get-NetAdapter | Where-Object { $_.InterfaceIndex -eq $InterfaceId }
    #Write-Log "[Test-InternetConnection] adapter='$($adapter.Name)' Status='$($adapter.Status)' MediaConnectionState='$($adapter.MediaConnectionState)'" "INFO"
    if ($null -eq $adapter) {
        return $false
    }
    
    # Check adapter status
    if ($adapter.Status -eq "Up" -and $adapter.MediaConnectionState -eq "Connected") {
        # Ckeck IP-address
        $sourceAddress = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $InterfaceId
        Write-Log "[Test-InternetConnection] sourceAddress='$($sourceAddress.IPAddress)'" "INFO"
        if ($sourceAddress.IPAddress -like "169.254.*") {
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

    # Отключаем DHCP, если он включен
    Set-NetIPInterface -InterfaceIndex $InterfaceId -Dhcp Disabled

    # Проверяем состояние DHCP
    $dhcpStatus = Get-NetIPInterface -InterfaceIndex $InterfaceId | Select-Object Dhcp
    Write-Log "Состояние DHCP для интерфейса $InterfaceId = $($dhcpStatus.Dhcp)" "INFO"

    # Remove IP address and gateways
    $existingIpAddresses = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $InterfaceId
    foreach ($ip in $existingIpAddresses) {
        Remove-NetIPAddress -InterfaceIndex $InterfaceId -IPAddress $ip.IPAddress -Confirm:$false
        Write-Log "Удален существующий IP-адрес: $($ip.IPAddress)" "INFO"
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
    $arguments = @{DNSDomainSuffixSearchOrder = @("")}  # Пустой массив для сброса

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

    # Получаем информацию о сетевом адаптере
    $adapter = Get-NetAdapter -InterfaceIndex $InterfaceId
    if ($adapter) {
        # Путь к реестру для настройки NetBIOS
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$($adapter.InterfaceGuid)"
        
        # Проверяем, существует ли путь к реестру
        if (Test-Path $registryPath) {
            # Получаем текущее значение NetBIOS
            $currentValue = Get-NetBiosOptions -InterfaceId $InterfaceId
            
            # Если текущее значение не совпадает с новым значением, обновляем его
            if ($currentValue -ne $NBTOption) {
                try {
                    Set-ItemProperty -Path $registryPath -Name "NetbiosOptions" -Value $NBTOption #-Verbose
                    
                    # Проверяем новое значение
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

    # Получаем информацию о сетевом адаптере
    $adapter = Get-NetAdapter -InterfaceIndex $InterfaceId
    if ($adapter) {
        # Путь к реестру для настройки NetBIOS
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$($adapter.InterfaceGuid)"
        
        # Проверяем, существует ли путь к реестру
        if (Test-Path $registryPath) {
            # Устанавливаем значение TcpipNetbiosOptions (0 - по умолчанию, 1 - включить, 2 - отключить)
            $propertyName = "NetbiosOptions"
            try {
                $currentValue = (Get-ItemProperty -Path $registryPath -Name $propertyName).$propertyName
                return $currentValue
            } catch {
                Write-Log "Ошибка при получении значения свойства '$propertyName': $_" "ERROR"
                return $null
            }
        } else {
            Write-Log "Путь к реестру '$registryPath' не существует." "ERROR"
            return $null
        }
    } else {
        Write-Log "Сетевой адаптер с InterfaceIndex $InterfaceId не найден." "ERROR"
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
        Write-Log "Ошибка при настройке WINS-серверов: $($Error[0].Message)" "ERROR"
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
            Write-Log "Decrypted configuration is empty." "ERROR"
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
    $Adapters = Get-NetAdapter | Where-Object { $_.MediaType -eq "802.3"  } #-and $_.Status -eq "Up"
    if ($Adapters.Count -eq 0) {
        Write-Log "No wired adapters available." "ERROR"
        return $null
    } elseif ($Adapters.Count -eq 1) {
        return $Adapters[0]
    } else {
        Write-Log "Multiple adapters found. Prompting user for selection." "INFO"
        for ($i = 0; $i -lt $Adapters.Count; $i++) {
            Write-Log "$($i + 1): $($Adapters[$i].InterfaceDescription)" "INFO"
        }
        do {
            $selection = Read-Host "Select adapter number (1-$($Adapters.Count)) or type 'q' to quit"
            if ($selection -eq 'q') {
                Write-Log "Administrator terminated the script." "INFO"
                return $null
            }
        } while (-not ($selection -as [int]) -or $selection -lt 1 -or $selection -gt $Adapters.Count)
        return $Adapters[$selection - 1]
    }
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
    $choiceDhcp = Read-Host "Do you want to use DHCP-server for adapter '$($SelectedAdapter.Name)' ? (Yes/No)"
    if ($choiceDhcp -match "(?i)^(n|no)$") {
        Write-Log "Skip reconfiguration for DHCP." "INFO" # пользователь отказался от настройки dhcp
        $choiceStatic = Read-Host "Do you want to use static params for adapter '$($SelectedAdapter.Name)' ? (Yes/No)"
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
            } # либо пользователь отказался от статики, либо настроена статика и перегрузили адаптер, либо ошибка настройки статики 
    } else { # пользователь выбрал dhcp
        Write-Log "Enabling DHCP..." "INFO"
        # Clean previous settings
        if (Clear-NetworkConfig -InterfaceId $InterfaceId) {
            Write-Log "Previous settings IP was cleared." "INFO"
            # Turn on DHCP
            Set-NetIPInterface -InterfaceIndex $InterfaceId -Dhcp Enabled -ManagedAddressConfiguration Enabled -Confirm:$false
            Write-Log "Waiting 20 seconds for applying DHCP configuration." "INFO"
            Restart-NetAdapter -Name $SelectedAdapter.Name
            Start-Sleep -Seconds 20
        } else { # не удачная очистка параметров сети на адаптере
            Write-Log "Clear-NetworkConfig was failed." "ERROR"
        } # dhcp либо настроен, либо выдано сообщение о неудачной попытке, но для попытки перенастроить на статику нужно перезапускать скрипт заново   
    } # тут либо настроен адаптер, но не тестировали соединение, либо выдана ошибка пояснения причины неудачи настройки
    if (Test-InternetConnection -InterfaceId $InterfaceId) {
        Write-Log "Adapter '$($SelectedAdapter.Name)' configured for Internet access successfully." "INFO"
    } else {        
        Write-Log "No internet connection for '$($SelectedAdapter.Name)'" "INFO"
    }
    # Display and log the new adapter settings
    $currentConfiguration = Get-NetworkAdapterProperties -InterfaceId $InterfaceId
    Write-Log $currentConfiguration "INFO"
}