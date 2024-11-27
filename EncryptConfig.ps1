param (
    [switch]$Help,    # Switch for displaying help
    [string]$JsonFilePath    # Path to the source JSON file
)

# Display help if -Help is specified
if ($Help) {
    Write-Host "Script for encrypting network configuration and testing decryption." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  .\EncryptConfig.ps1 -JsonFilePath <path_to_json_file>"
    Write-Host ""
    Write-Host "Parameters:"
    Write-Host "  -JsonFilePath   Path to the JSON file with configuration parameters. (Required)"
    Write-Host "  -Help           Display this message and exit."
    exit
}

# Check if the required parameter is provided
if (-not $JsonFilePath) {
    Write-Host "Error: The configuration file path is not specified. Use -JsonFilePath to provide the path." -ForegroundColor Red
    exit 1
}

# Check if the configuration file exists
if (-not (Test-Path -Path $JsonFilePath)) {
    Write-Host "Configuration file not found: $JsonFilePath" -ForegroundColor Red
    exit 1
}

# Load the JSON configuration file
try {
    $jsonContent = Get-Content -Raw -Path $JsonFilePath -Encoding UTF8
    $jsonTest = $jsonContent | ConvertFrom-Json
    Write-Host "Configuration successfully loaded and validated from file: $JsonFilePath" -ForegroundColor Green
} catch {
    Write-Host "Error reading or validating the JSON file: $_" -ForegroundColor Red
    exit 1
}

# Prompt the user to enter a password for encryption
$password = Read-Host -Prompt "Enter a password for encryption" -AsSecureString

# Convert the SecureString password to a plain string
$plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))

try {
    # Generate a key for encryption based on the password (SHA-256)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $keyFromPassword = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($plainPassword))
    Write-Host "Encryption key successfully generated based on the password." -ForegroundColor Green
} catch {
    Write-Host "Error generating encryption key from the password: $_" -ForegroundColor Red
    exit 1
}

# Encrypt the configuration content
try {
    $secureString = ConvertTo-SecureString -String $jsonContent -AsPlainText -Force
    $encryptedString = ConvertFrom-SecureString -SecureString $secureString -Key $keyFromPassword
    Write-Host "Configuration successfully encrypted." -ForegroundColor Green
} catch {
    Write-Host "Error encrypting the configuration: $_" -ForegroundColor Red
    exit 1
}

# Determine the path to save the encrypted file
$encryptedFilePath = "$($JsonFilePath).enc"

try {
    Set-Content -Path $encryptedFilePath -Value $encryptedString -Encoding UTF8
    $fullEncryptedFilePath = Resolve-Path -Path $encryptedFilePath
    Write-Host "Encrypted file saved at: " -NoNewline -ForegroundColor Green
    Write-Host $fullEncryptedFilePath -ForegroundColor Blue
} catch {
    Write-Host "Error saving the encrypted file: $_" -ForegroundColor Red
    exit 1
}
