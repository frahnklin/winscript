<#
  Franklin's Windows 10/11 Script
  -------------------------------------------------------
  | The purpose of this script is to fix the problems   |
  | with recent versions of Windows, namely Windows 10  |
  | and windows 11. This script aims to disable all the |
  | telemetry data and unnecessary services, remove all |
  | the bloatware, and have Windows act like it should. |
  |                                                     |
  | Inspiration scripts:                                |
  | - Chris Titus' Windows Script                       |
  | - Sycnex Windows 10 Debloater                       |
  | - Windows Ameliorated Edition                       |
  | - 2020-Decrapify by Disassembler                    |
  -------------------------------------------------------
#>

# Run as administrator if not done so by user
# Disabled: causes errors when script is run via "iwr winscript.ps1 | iex"
# If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
#   Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
#   Exit
# }
  
# -------------------------------------------------------------------------------------------- #
# Stage 1: Prepare system for debloat

#clear-host
Write-Host "-----------------------------"
Write-Host "| Franklin's Debloat Script |"
Write-Host "-----------------------------"

Write-Host "`nWelcome to the Windows 10/11 Debloater!"
Write-Host "`nThis script aims to fix the problems with Windows 10/11."
Write-Host "Telemetry is disabled, bloat is removed, and optimizations are made."

Write-Host "`nStarting stage 1 of debloat: preparing system...`n"

# Input validation loop for each prompt until either 'Y', 'y', 'N', or 'n' is typed
Do { $winget = (Read-Host "Install Winget? (Y/N)").ToLower() } Until (($winget -eq 'y') -or ($winget -eq 'n'))
Do { $wingetApps = (Read-Host "Install Chromium and 7-Zip? (Y/N)").ToLower() } Until (($wingetApps -eq 'y') -or ($wingetApps -eq 'n'))
Do { $epInstall = (Read-Host "Install ExplorerPatcher (for Windows 11)? (Y/N)").ToLower() } Until (($epInstall -eq 'y') -or ($epInstall -eq 'n'))
Do { $removeStartAndTbPins = (Read-Host "Remove Start Menu and Taskbar Pins? (Only advised for new installs) (Y/N)").ToLower() } Until (($removeStartAndTbPins -eq 'y') -or ($removeStartAndTbPins -eq 'n'))
Do { $uwpRemove = (Read-Host "Remove (almost) all stock UWP apps? (Y/N)").ToLower() } Until (($uwpRemove -eq 'y') -or ($uwpRemove -eq 'n'))
Do { $edgeRemove = (Read-Host "Remove Microsoft Edge? (Y/N)").ToLower() } Until (($edgeRemove -eq 'y') -or ($edgeRemove -eq 'n'))
Do { $svcDel = (Read-Host "Permanently delete tracking services? (Y/N)").ToLower() } Until (($svcDel -eq 'y') -or ($svcDel -eq 'n'))
Do { $featsAndCapabs = (Read-Host "Remove unnecessary Windows Features and Capabilities? (Y/N)").ToLower() } Until (($featsAndCapabs -eq 'y') -or ($featsAndCapabs -eq 'n'))
Do { $restart = (Read-Host "Automatically restart PC when done? (Y/N)").ToLower() } Until (($restart -eq 'y') -or ($restart -eq 'n'))

# Convert 'y' or 'n' to $true or $false
$winget = Switch ($winget) { 'y' { $true }; 'n' { $false } }
$wingetApps = Switch ($wingetApps) { 'y' { $true }; 'n' { $false } }
$epInstall = Switch ($epInstall) { 'y' { $true }; 'n' { $false } }
$rmStartAndTbPins = Switch ($rmStartAndTbPins) { 'y' { $true }; 'n' { $false } }
$uwpRemove = Switch ($uwpRemove) { 'y' { $true }; 'n' { $false } }
$edgeRemove = Switch ($edgeRemove) { 'y' { $true }; 'n'  { $false } }
$svcDel = Switch ($svcDel) { 'y' { $true }; 'n' { $false } }
$featsAndCapabs = Switch ($featsAndCapabs) { 'y' { $true }; 'n' { $false } }
$restart = Switch ($restart) { 'y' { $true }; 'n' { $false } }

#clear-host

If ($winget -eq $true) {
  # Install Winget
  Write-Host "Installing winget..."
  Start-BitsTransfer -Source "https://globalcdn.nuget.org/packages/microsoft.ui.xaml.2.7.1.nupkg" -Destination "$env:temp\xaml.zip"
  Expand-Archive $env:temp\xaml.zip -DestinationPath $env:temp -Force
  Add-AppxPackage -Path $env:temp\tools\Appx\x64\release\Microsoft.UI.Xaml.2.7.appx
  Start-BitsTransfer -Source "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx" -Destination "$env:temp\vclibs.appx"
  Add-AppxPackage -Path $env:temp\vclibs.appx
  Start-BitsTransfer -Source "https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -Destination "$env:temp\appinstaller.msixbundle"
  Add-AppxPackage -Path $env:temp\appinstaller.msixbundle
}

If ($wingetApps -eq $true) {
  # Install Winget apps
  $Apps = (
    "Hibbiki.Chromium",
    "7zip.7zip"
  )

  If (Get-Command winget -ErrorAction SilentlyContinue) {
    ForEach ($app in $apps) {
      winget install --id $app -e --accept-package-agreements --accept-source-agreements
    }
  } Else {
    Write-Host "Winget not found; can't install apps!"
  }
}

If ($epInstall -eq $true) {
  # Windows 11 specific tweaks
  If (((Get-CimInstance Win32_OperatingSystem).BuildNumber) -gt 20000) {
    Start-BitsTransfer -Source "https://github.com/valinet/ExplorerPatcher/releases/latest/download/ep_setup.exe" -Destination "$env:temp\epsetup.exe"
    Start-Process $env:temp\epsetup.exe
    Start-Sleep -Seconds 20
    Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
    reg.exe add "HKCU\Software\ExplorerPatcher" /v OldTaskbar /t REG_DWORD /d 0 /f
    reg.exe add "HKCU\Software\ExplorerPatcher" /v ClockFlyoutOnWinC /t REG_DWORD /d 1 /f
    reg.exe add "HKCU\Software\ExplorerPatcher" /v DisableWinFHotkey /t REG_DWORD /d 1 /f
    reg.exe add "HKCU\Software\ExplorerPatcher" /v DoNotRedirectSystemToSettingsApp /t REG_DWORD /d 1 /f
    reg.exe add "HKCU\Software\ExplorerPatcher" /v DoNotRedirectProgramsAndFeaturesToSettingsApp /t REG_DWORD /d 1 /f
    reg.exe add "HKCU\Software\ExplorerPatcher" /v DoNotRedirectDateAndTimeToSettingsApp /t REG_DWORD /d 1 /f
    reg.exe add "HKCU\Software\ExplorerPatcher" /v DoNotRedirectNotificationIconsToSettingsApp /t REG_DWORD /d 1 /f
  }
}

Stop-Process -Name explorer -ErrorAction SilentlyContinue

# -------------------------------------------------------------------------------------------- #
# Stage 2: Privacy tweaks and edits

#clear-host
Write-Host "Stage 1 of debloat finished."
Write-Host "Starting stage 2 of debloat: privacy tweaks..."

$tasks = (
  "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
  "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
  "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
  "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
  "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
  "\Microsoft\Windows\Feedback\Siuf\DmClient",
  "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
  "Microsoft\Windows\Windows Error Reporting\QueueReporting",
  "\Microsoft\Windows\Application Experience\StartupAppTask",
  "\Microsoft\Windows\Clip\License Validation",
  "\Microsoft\Windows\HelloFace\FODCleanupTask",
  "\Microsoft\Windows\Maps\MapsToastTask",
  "\Microsoft\Windows\Maps\MapsUpdateTask",
  "\MicrosoftEdgeUpdateTaskCore",
  "\MicrosoftEdgeUpdateTaskUA"
)

ForEach ($task in $tasks) {
  schtasks.exe /change /TN $task /DISABLE
  schtasks.exe /delete /TN $task /f
}

# Privacy tweaks
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f 
reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSync /t REG_DWORD /d 2 /f 
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSyncUserOverride /t REG_DWORD /d 1 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f 
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f 
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EnhancedStorageDevices" /v TCGSecurityActivationDisabled /t REG_DWORD /d 0 /f 
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v DontSendAdditionalData /t REG_DWORD /d 1 /f 
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f 
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v value /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v ContentDeliveryAllowed /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v OemPreInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEverEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338387Enabled /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338388Enabled /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353698Enabled /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v NoTileApplicationNotification /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v SensorPermissionState /t REG_DWORD /d 1 /f
reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /f
reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudClient" /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d 1 /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "DisablePrivacyExperience" /t REG_DWORD /d "1" /f
reg.exe add "HKEY_USERS\.DEFAULT\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Settings\FindMyDevice" /v "LocationSyncEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "1" /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d "1" /f
reg.exe add "HKEY_USERS\.DEFAULT\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f

# Disable Windows Autologger
Write-Output "" > C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f 
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f 
icacls C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger /deny SYSTEM:`(OI`)`(CI`)F
icacls C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger /deny everyone:`(OI`)`(CI`)F

# Disable Cortana
reg.exe add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v AcceptedPrivacyPolicy /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v HarvestContacts /t REG_DWORD /d 0 /f

# Fix Windows Search
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f 
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f 
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowIndexingEncryptedStoresOrItems" /t REG_DWORD /d 0 /f 
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f 
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AlwaysUseAutoLangDetection" /t REG_DWORD /d 0 /f 
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f 
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f 
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaInAmbientMode" /t REG_DWORD /d 0 /f 
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "HistoryViewEnabled" /t REG_DWORD /d 0 /f  
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "HasAboveLockTips" /t REG_DWORD /d 0 /f 
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f 
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "SafeSearchMode" /t REG_DWORD /d 0 /f 
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f 
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f 
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f 
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f 
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d 0 /f 
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d 0 /f
$hkuPath = $(reg.exe query HKEY_USERS | Select-String -NotMatch -Pattern 'S-1-5-19|S-1-5-20|S-1-5-18|.Default|Classes')
reg.exe add $hkuPath\Software\Policies\Microsoft\Windows\Explorer /v DisableSearchBoxSuggestions /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /v "Block Search SearchApp.exe" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe|Name=Block Search SearchUI.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|" /f 

# Disable inking and typing
reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f 
reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f 
reg.exe add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f 
reg.exe add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f

# Disable speech recognition
reg.exe add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationDefaultOn" /t REG_DWORD /d 0 /f 
reg.exe add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationEnableAboveLockscreen" /t REG_DWORD /d 0 /f 
reg.exe add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v "ModelDownloadAllowed" /t REG_DWORD /d 0 /f 
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "DisableVoice" /t REG_DWORD /d 1 /f

# Disable user activity
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d 0 /f 
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d 0 /f 
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d 0 /f 

# Fix Windows Explorer
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /t REG_DWORD /d 1 /f 
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f 
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f 
reg.exe delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.bmp\Shell\3D Edit" /f 
reg.exe delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.jpeg\Shell\3D Edit" /f 
reg.exe delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.jpe\Shell\3D Edit" /f 
reg.exe delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.jpg\Shell\3D Edit" /f 
reg.exe delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.jpg\Shell\3D Edit" /f 
reg.exe delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.png\Shell\3D Edit" /f 
reg.exe delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.gif\Shell\3D Edit" /f 
reg.exe delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.tif\Shell\3D Edit" /f 
reg.exe delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.tiff\Shell\3D Edit" /f 

# Remove bloatware registry entries
reg.exe delete "HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y" /f
reg.exe delete "HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0" /f
reg.exe delete "HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe" /f
reg.exe delete "HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy" /f
reg.exe delete "HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy" /f
reg.exe delete "HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy" /f
reg.exe delete "HKCR\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0" /f
reg.exe delete "HKCR\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y" /f
reg.exe delete "HKCR\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0" /f
reg.exe delete "HKCR\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy" /f
reg.exe delete "HKCR\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy" /f
reg.exe delete "HKCR\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy" /f
reg.exe delete "HKCR\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe" /f
reg.exe delete "HKCR\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0" /f
reg.exe delete "HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy" /f
reg.exe delete "HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy" /f
reg.exe delete "HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy" /f
reg.exe delete "HKCR\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0" /f

# -------------------------------------------------------------------------------------------- #
# Stage 3: Quality-of-life tweaks

#clear-host
Write-Host "Stage 2 of debloat finished."
Write-Host "Starting stage 3 of debloat: performance and feature tweaks..."

# Clean up clutter
If ($rmStartAndTbPins -eq $true) {
  # Remove Bloat Apps from Start Menu Pins
  Stop-Process -Name StartMenuExperienceHost -ErrorAction SilentlyContinue
  reg.exe delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount" /f
  # Remove Taskbar Pins
  Stop-Process -Name explorer -ErrorAction SilentlyContinue
  Remove-Item $env:AppData\"Microsoft\Internet Explorer\Quick Launch\User Pinned\Taskbar\*" -Force
  Remove-Item $env:AppData\"Microsoft\Internet Explorer\Quick Launch\User Pinned\ImplicitAppShortcuts\*" -Force
  reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" /f
}
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v PeopleBand /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v EnableFeeds /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsTaskbarViewMode /t REG_DWORD /d 2 /f

# Set UTC Time
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" /v RealTimeIsUniversal /t REG_DWORD /d 1 /f 

# Enable highest UAC level
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f

# Fix Windows Update
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" /v DontPromptForWindowsUpdate /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" /v DontSearchWindowsUpdate /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" /v DriverUpdateWizardWuSearchEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v SearchOrderConfig /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v ExcludeWUDriversInQualityUpdate /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUPowerManagement /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v BranchReadinessLevel /t REG_DWORD /d 20 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v DeferFeatureUpdatesPeriodInDays /t REG_DWORD /d 365 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v DeferQualityUpdatesPeriodInDays /t REG_DWORD /d 4 /f
reg.exe add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v UxOption /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DownloadMode /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 1 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v SystemSettingsDownloadMode /t REG_DWORD /d 3 /f

# Enable long paths
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f
reg.exe add "HKCU\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f

# Disable feedback
reg.exe add "HKCU\Software\Microsoft\Siuf\Rules" /v PeriodInNanoSeconds /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f

# Wi-Fi tweaks
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v value /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f 
reg.exe add "HKCU\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v IRPStackSize /t REG_DWORD /d 2 /f
reg.exe add "HKLM\SOFTWARE\MicrosoftWindows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 4294967295 /f

# Gaming tweaks
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 6 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f

# Enable legacy bootmenu with F8 on startup
bcdedit.exe /set `{default`} bootmenupolicy legacy

# Fix power settings
powercfg.exe /h off
powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

# Fix MS-MSDT Follina exploit
reg.exe delete HKEY_CLASSES_ROOT\ms-msdt /f

# Disable SMBv1 to mitigate WannaCry
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
# sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi
sc.exe config mrxsmb10 start= disabled

# Remove Windows Meet Now in Taskbar
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarMn /t REG_DWORD /d 0 /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Chat" /v ChatIcon /t REG_DWORD /d 3 /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAMeetNow /t REG_DWORD /d 1 /f

# Disable " - Shortcut" text for shortcuts
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v link /t REG_BINARY /d "00 00 00 00" /f

# Remove Context Menu Entries
# Scan With Defender
reg.exe delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f
reg.exe delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f
# Cast To Device
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" /t REG_SZ /f
# BitLocker-related menus
reg.exe add "HKCR\Drive\shell\change-passphrase" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\Drive\shell\change-pin" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\Drive\shell\encrypt-bde" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\Drive\shell\encrypt-bde-elev" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\Drive\shell\manage-bde" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\Drive\shell\resume-bde" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\Drive\shell\resume-bde-elev" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\Drive\shell\unlock-bde" /v ProgrammaticAccessOnly /t REG_SZ /f
# Edit With Photos
reg.exe add "HKCR\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellEdit" /v ProgrammaticAccessOnly /t REG_SZ /f
# Edit With Paint 3D
reg.exe delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.bmp\Shell" /f 
reg.exe delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.jpeg\Shell" /f 
reg.exe delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.jpe\Shell" /f 
reg.exe delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.jpg\Shell" /f 
reg.exe delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.png\Shell" /f 
reg.exe delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.gif\Shell" /f 
reg.exe delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.tif\Shell" /f 
reg.exe delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.tiff\Shell" /f
# Give Access To
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{f81e9010-6ea4-11ce-a7ff-00aa003ca9f6}" /t REG_SZ /f
# Share
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{e2bf9676-5f8f-435c-97eb-11607a5bedf7}" /t REG_SZ /f
# Restore Previous Versions
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{596AB062-B4D2-4215-9F74-E9109B0A8153}" /t REG_SZ /f
# Pin To Start
reg.exe add "HKEY_CLASSES_ROOT\exefile\shellex\ContextMenuHandlers\PintoStartScreen" /v "{470C0EBD-5D73-4d58-9CED-E91E22E23282}" /t REG_SZ /f
# Pin To Taskbar
reg.exe delete "HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers" /v "{90AA3A4E-1CBA-4233-B8BB-535773D48449}" /f
# Troubleshoot Compatibility
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{1d27f844-3a1f-4410-85ac-14651078412d}" /t REG_SZ /f
# Windows Media Player
reg.exe add "HKCR\SystemFileAssociations\audio\shell\Play" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\Stack.Audio\shell\Play" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\Stack.Video\shell\Play" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\Stack.Image\shell\Play" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\SystemFileAssociations\Directory.VIDEO\shell\Play" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\SystemFileAssociations\audio\shell\Play" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\SystemFileAssociations\Directory.Audio\shell\Play" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\SystemFileAssociations\Directory.Image\shell\Play" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\MediaCenter.WTVFile\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\Stack.Audio\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\Stack.Image\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\Stack.Video\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\SystemFileAssociations\audio\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\SystemFileAssociations\Directory.Audio\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\SystemFileAssociations\Directory.VIDEO\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\SystemFileAssociations\Directory.Image\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\WMP.DVR-MSFile\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\WMP.WTVFile\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\WMP11.AssocFile.3G2\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\WMP11.AssocFile.3GP\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\WMP11.AssocFile.ADTS\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\WMP11.AssocFile.AIFF\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\WMP11.AssocFile.ASF\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\WMP11.AssocFile.ASX\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\WMP11.AssocFile.AU\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\WMP11.AssocFile.AVI\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\WMP11.AssocFile.FLAC\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\WMP11.AssocFile.M2TS\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\WMP11.AssocFile.m3u\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\WMP11.AssocFile.M4A\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\WMP11.AssocFile.MIDI\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\WMP11.AssocFile.MK3D\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\WMP11.AssocFile.MKA\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\WMP11.AssocFile.MKV\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\WMP11.AssocFile.MOV\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\WMP11.AssocFile.MP3\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\WMP11.AssocFile.MP4\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\WMP11.AssocFile.MPEG\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\WMP11.AssocFile.TTS\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\WMP11.AssocFile.WAV\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\WMP11.AssocFile.WAX\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\WMP11.AssocFile.WMA\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\WMP11.AssocFile.WMV\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\WMP11.AssocFile.WPL\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\WMP11.AssocFile.WVX\shell\Enqueue" /v ProgrammaticAccessOnly /t REG_SZ /f
# Include In Library
reg.exe delete "HKCR\Folder\ShellEx\ContextMenuHandlers" /v "Library Location" /f
# Create a New Video
reg.exe add "HKCR\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellCreateVideo" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\AppXk0g4vb8gvt7b93tg50ybcy892pge6jmt\Shell\ShellCreateVideo" /v ProgrammaticAccessOnly /t REG_SZ /f
# Move to OneDrive
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{CB3D0F55-BC2C-4C1A-85ED-23ED75B5106B}" /t REG_SZ /f
# File Ownership EFS
reg.exe add "HKCR\*\shell\UpdateEncryptionSettingsWork" /v ProgrammaticAccessOnly /t REG_SZ /f
reg.exe add "HKCR\Directory\shell\UpdateEncryptionSettings" /v ProgrammaticAccessOnly /t REG_SZ /f
# Open in Windows Terminal / Windows Terminal Preview
# reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{9F156763-7844-4DC4-B2B1-901F640F5155}" /t REG_SZ /F
# reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{02DB545A-3E20-46DE-83A5-1329B1E88B6B}" /t REG_SZ /F
# Add To Favorites
reg.exe add "HKCR\*\shell\pintohomefile" /v ProgrammaticAccessOnly /t REG_SZ /f
# Run as Different User
reg.exe delete "HKCR\batfile\shell\runasuser" /f
reg.exe delete "HKCR\cmdfile\shell\runasuser" /f
reg.exe delete "HKCR\exefile\shell\runasuser" /f
reg.exe delete "HKCR\mscfile\shell\runasuser" /f
reg.exe delete "HKCR\Msi.Package\shell\runasuser" /f

# Disable Microsoft Edge previews in Alt-Tab
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v MultiTaskingAltTabFilter /t REG_DWORD /d 3 /f

# Disable bad multitasking features on Windows 11
If (((Get-CimInstance Win32_OperatingSystem).BuildNumber) -gt 20000) {
  reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v EnableSnapbar /t REG_DWORD /d 0 /f
  reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v EnableSnapAssistFlyout /t REG_DWORD /d 0 /f
  reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v EnableTaskGroups /t REG_DWORD /d 0 /f
  reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v SnapAssist /t REG_DWORD /d 0 /f
}

# Enable Windows 11 22H2 Education Edition Themes
If (((Get-CimInstance Win32_OperatingSystem).BuildNumber) -gt 22621) {
  reg.exe add "HKLM\Software\Microsoft\PolicyManager\current\device" /v EnableEduThemes /t REG_DWORD /d 1 /f
}

# Fixing Windows Explorer CPU Usage
reg.exe add "HKCU\SOFTWARE\Microsoft\input" /v IsInputAppPreloadEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Dsh" /v IsPrelaunchEnabled /t REG_DWORD /d 0 /f

# Harden Windows by enabling mitigations
'<?xml version="1.0" encoding="UTF-8"?>
<MitigationPolicy>
  <SystemConfig>
    <ASLR ForceRelocateImages="true" RequireInfo="false" BottomUp="true" HighEntropy="true" />
    <SEHOP Enable="true" TelemetryOnly="false" />
    <Heap TerminateOnError="true" />
  </SystemConfig>
</MitigationPolicy>' | Out-File $env:temp\exploit_protection.xml

Set-ProcessMitigation -PolicyFilePath $env:temp\exploit_protection.xml

# Misc. tweaks I don't know how to categorize
reg.exe add "HKCU\Control Panel\International\User Profile" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f 
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v Status /t REG_DWORD /d 0 /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Holographic" /v FirstRunSucceeded /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f


# -------------------------------------------------------------------------------------------- #
# Stage 4: UWP debloat, Microsoft Edge, and Microsoft Teams Removal

#clear-host
Write-Host "Stage 3 of debloat finished."
Write-Host "Starting stage 4 of debloat: UWP bloatware removal..."

If ($uwpRemove -eq $true) {
  $Bloatware = @(
    #Unnecessary Windows 10 AppX Apps
    "549981C3F5F10",
    "3DBuilder",
    "Microsoft3DViewer",
    "AppConnector",
    "Advertising",
    "BingFinance",
    "BingNews",
    "BingSports",
    "BingTranslator",
    "BingWeather",
    "BingFoodAndDrink",
    "BingHealthAndFitness",
    "BingTravel",
    "Cortana",
    "ClipChamp",
    "Camera",
    "Edge",
    "GamingServices",
    "GamingApp"
    "GetHelp",
    "Getstarted",
    "Messaging",
    "Microsoft3DViewer",
    "MicrosoftOfficeHub",
    "MicrosoftSolitaireCollection",
    # "MinecraftUWP",
    "MixedReality.Portal",
    # "MSPaint",
    "NetworkSpeedTest",
    "News",
    "Lens",
    "Sway",
    "OneNote",
    "OneConnect",
    "Office",
    "Office.Lens",
    "Office.Sway",
    "Office.Todo.List",
    "People",
    "Photos",
    "PowerAutomate",
    "Print3D",
    "QuickAssist"
    "SkypeApp",
    "StickyNotes"
    "PPIProjection",
    "Todos",
    "Teams",
    # "Terminal",
    "Wallet",
    "WebExperience"
    "Whiteboard",
    "WindowsAlarms",
    "windowscommunicationsapps",
    "WindowsFeedbackHub",
    "WindowsMaps",
    "WindowsPhone",
    "WindowsSoundRecorder",
    # "XboxApp",
    "ConnectivityStore",
    "CommsPhone",
    "TCUI",
    # "XboxGameCallableUI",
    "XboxIdentityProvider",
    "XboxSpeechToTextOverlay",
    "ZuneMusic",
    "ZuneVideo",
    "YourPhone",
    "Getstarted",
    "MicrosoftOfficeHub",
    "EclipseManager",
    "ActiproSoftwareLLC",
    "AdobeSystemsIncorporated.AdobePhotoshopExpress",
    "Duolingo-LearnLanguagesforFree",
    "PandoraMediaInc",
    "CandyCrush",
    "BubbleWitch3Saga",
    "Wunderlist",
    "Flipboard",
    "Twitter",
    "Facebook",
    "Royal Revolt",
    "Sway",
    "Speed Test",
    "Dolby",
    "Viber",
    "ACGMediaPlayer",
    "Netflix",
    "OneCalendar",
    "LinkedInforWindows",
    "HiddenCityMysteryofShadows",
    "Hulu",
    "HiddenCity",
    "AdobePhotoshopExpress",
    "HotspotShieldFreeVPN",
    "Advertising",
    "HPJumpStarts",
    "HPPCHardwareDiagnosticsWindows",
    "HPPowerManager",
    "HPPrivacySettings",
    "HPSupportAssistant",
    "HPSureShieldAI",
    "HPSystemInformation",
    "HPQuickDrop",
    "HPWorkWell",
    "myHP",
    "HPDesktopSupportUtilities",
    "HPQuickTouch",
    "HPEasyClean",
    "HPSystemInformation"
  #	"HEIFImageExtension",
  #	"VP9VideoExtensions",
  #	"WebMediaExtensions",
  #	"WebpImageExtension"
  )

  ForEach ($Bloat in $Bloatware) {
    Get-AppxPackage "*$Bloat*" | Remove-AppxPackage -ErrorAction SilentlyContinue
    Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*$Bloat*" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    Write-Host "Trying to remove $Bloat."
  }
}

If($edgeRemove -eq $true) {
  # Remove Microsoft Edge
  sc.exe stop edgeupdate
  sc.exe stop edgeupdatem
  sc.exe delete edgeupdate
  sc.exe delete edgeupdatem
  Stop-Process -Name MicrosoftEdgeUpdate -Force -ErrorAction SilentlyContinue
  Stop-Process -Name msedge -Force -ErrorAction SilentlyContinue
  Start-BitsTransfer -Source "https://raw.githubusercontent.com/AveYo/fox/main/Edge_Removal.bat" -Destination "$env:temp\edge_removal.bat"
  Start-Process $env:temp\edge_removal.bat
  Start-Sleep -Seconds 30
  Set-Location $env:USERPROFILE

  $folders = (
    "C:\Program Files (x86)\Microsoft\Edge",
    "C:\Program Files (x86)\Microsoft\EdgeUpdate",
    "C:\Program Files (x86)\Microsoft\EdgeCore",
    "C:\Program Files (x86)\Microsoft\EdgeWebView",
    "AppData\Local\Microsoft\Edge",
    "AppData\Local\Microsoft\EdgeCore",
    "AppData\Local\Microsoft\EdgeUpdate"
  )

  ForEach ($folder in $folders) {
    If (Test-Location $folder) {
      takeown.exe /f $folder
      icacls.exe $folder /grant everyone:f
      Remove-Item -Recurse $folder -Force -ErrorAction SilentlyContinue
      New-Item -Name $folder -ItemType "directory" -ErrorAction SilentlyContinue
      icacls.exe $folder /deny everyone:`(OI`)`(CI`)F
      # icacls.exe $folder /deny SYSTEM:`(OI`)`(CI`)F
      # icacls.exe $folder /deny TrustedInstaller:`(OI`)`(CI`)F
    }
  }

  Remove-Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk" -Force -ErrorAction SilentlyContinue
  Remove-Item $env:USERPROFILE\Desktop\"Microsoft Edge.lnk" -Force -ErrorAction SilentlyContinue
  Remove-Item "C:\Users\Public\Public Desktop\Microsoft Edge.lnk" -Force -ErrorAction SilentlyContinue
}

# Microsoft Edge registry policy enforcal
# Privacy tweaks
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v SyncDisabled /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v BrowserSignin /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v AutoImportAtFirstRun /t REG_DWORD /d 4 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v DiagnosticData /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v PersonalizationReportingEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v PasswordManagerEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v PasswordMonitorAllowed /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v AutofillAddressEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v AutofillCreditCardEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v PaymentMethodQueryEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v LocalBrowserDataShareEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v TrackingPrevention /t REG_DWORD /d 3 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v ConfigureDoNotTrack /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v DnsOverHttpsMode /t REG_SZ /d "secure" /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v DnsOverHttpsTemplates /t REG_SZ /d "https://dns.adguard-dns.com/dns-query" /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v SendSiteInfoToImproveServices /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v SiteSafetyServicesEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v AlternateErrorPagesEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v MicrosoftEditorProofingEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v MicrosoftEditorSynonymsEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v EdgeAssetDeliveryServiceEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v SpotlightExperiencesAndRecommendationsEnabled /t REG_DWORD /d 0 /f
# Bloat features tweaks
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v NewTabPageAppLauncherEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v NewTabPageContentEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v NewTabPageHideDefaultTopSites /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v NewTabPageQuickLinksEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v SearchInSidebarEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v ShowMicrosoftRewards /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v EdgeShoppingAssistantEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v PinningWizardAllowed /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v PromotionalTabsEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v RedirectSitesFromInternetExplorerPreventBHOInstall /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v RedirectSitesFromInternetExplorerRedirectMode /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v HideInternetExplorerRedirectUXForIncompatibleSitesEnabled /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v InternetExplorerIntegrationCloudUserSitesReporting /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v EdgeDiscoverEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v HubsSidebarEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v FamilySafetySettingsEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v EdgeFollowEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v VerticalTabsAllowed /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v WebWidgetAllowed /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v WebWidgetIsEnabledOnStartup /t REG_DWORD /d 0 /f
# Quality-of-life tweaks
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v BingAdsSuppression /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v RestoreOnStartup /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v DefaultSearchProviderEnabled /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v DefaultSearchProviderName /t REG_SZ /d "Google" /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v DefaultSearchProviderKeyword /t REG_SZ /d "google" /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v DefaultSearchProviderSearchURL /t REG_SZ /d "{google:baseURL}search?q={searchTerms}&{google:originalQueryForSuggestion}{google:searchFieldtrialParameter}{google:searchClient}{google:sourceId}ie={inputEncoding}" /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v DefaultSearchProviderSuggestURL /t REG_SZ /d "{google:baseURL}complete/search?output=chrome&q={searchTerms}" /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v DefaultSearchProviderImageURL /t REG_SZ /d "{google:baseURL}searchbyimage/upload" /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v NewTabPageSearchBox /t REG_SZ /d "redirect" /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v AddressBarMicrosoftSearchInBingProviderEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v SmartScreenPuaEnabled /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v EnhanceSecurityMode /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v ShowHomeButton /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v BackgroundModeEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v StartupBoostEnabled /t REG_DWORD /d 0 /f

# Uninstall Microsoft Teams
If (Test-Location $env:LOCALAPPDATA\Microsoft\Teams\update.exe) {
  Start-Process $env:LOCALAPPDATA\Microsoft\Teams\update.exe "-uninstall -s" }
Remove-Item -Recurse $env:LOCALAPPDATA\Microsoft\Teams -ErrorAction SilentlyContinue

# -------------------------------------------------------------------------------------------- #
# Stage 5: Disabling of services

#clear-host
Write-Host "Stage 4 of debloat finished."
Write-Host "Starting stage 5 of debloat: disabling services..."

$svcsToDisable = (
  "AJRouter",
  "ALG",
  "tzautoupdate",
  "BthAvctpSvc",
  "BTAGService",
  "PeerDistSvc",
  "autotimesvc",
  "CertPropSvc",
  "NfsClnt",
  "DiagTrack",
  "diagnosticshub.standardcollector.service",
  "cbdhsvc",
  "dmwappushservice",
  "dmwappushsvc",
  "MapsBroker",
  "Fax",
  "HomeGroupListener",
  "HomeGroupProvider",
  "ndu",
  "lfsvc",
  "InventorySvc",
  "HvHost",
  "gcs",
  "vmickvpexchange",
  "vmicguestinterface",
  "vmicshutdown",
  "vmicheartbeat",
  "vmcompute",
  "vmicvmsession",
  "vmicrdv",
  "vmictimesync",
  "vmicvss",
  "irmon",
  "CellularTime",
  "SharedAccess",
  "iphlpsvc",
  "IpxlatCfgSvc",
  "AppVClient",
  "SmsRouter",
  "NaturalAuthentication",
  "Netlogon",
  "CscService",
  "dSvc",
  "SEMgrSvc",
  "PhoneSvc",
  "PcaSvc",
  "WPDBusEnum",
  # "SessionEnv",
  # "TermService",
  "RpcLocator",
  "ReomteAccess",
  "RemoteRegistry",
  "RetailDemo",
#	"seclogon",
  "SstpSvc",
  "StiSvc",
  "spectrum",
  "perceptionsimulation",
  "SensorDataService",
  "SensrSvc",
  "SensorService",
  "shpamsvc",
  "SCardSvr",
  "ScDeviceEnum",
  "SCPolicySvc",
  "SNMPTRAP",
  "UevAgentService",
  "WebClient",
  "FrameServer",
  "FrameServerMonitor",
  "icssvc",
  "WalletService",
  "WpcMonSvc",
  "wcncsvc",
  "wisvc",
  "WinRM",
  "WwanSvc",
  # "MicrosoftEdgeElevationService",
  # "edgeupdate",
  # "edgeupdatem",
  "TrkWks",
  "FontCache",
  "PerfHost",
  "WMPNetworkSvc",
  "WpmService",
  "RtkBtManServ",
  "NahimicService",
  "NetTcpPowerSharing",
  "MSDTC",
  "DevicePickerUserSvc",
  "MessagingService",
  "OneSyncSvc",
  "PimIndexMaintenanceSvc",
  "UnistoreSvc",
  "lmhosts",
  # "SSDPSRV",
  "AppReadiness",
  # "LanmanWorkstation",
  "CmService",
  # "bowser",
  # "DusmSvc",
  "WbioSrvc",
  "HNS",
  "PenService",
  # "FDResPub",
  # "fdPHost",
  "Wcmsnetwvc",
  "nvagent",
  "LanmanServer",
  "TieringEngineService",
  "MixedRealityOpenXRSvc",
  "WMIRegistrationService",
  "Intel(R) Capability Licensing Service TCP IP Interface",
  "jhi_service",
  "Intel(R) TPM Provisioning Service",
  "EntAppSvc",
  "MSiSCSI",
  "p2pimsvc",
  "p2psvc",
  "PNRPsvc",
  "P9RdrService",
  "WerSvc",
  "dot3svc",
  "dcsvc",
  "AxInstSV",
  "AarSvc",
  "GrahicsPerfSvc",
  # "DPS",
  # "WdiServiceHost",
  # "WdiSystemHost",
  "DsSvc",
  "BluetoothUserService",
  "GamingServices",
  "GamingServicesNet",
  "GameInput Service",
  # "DisplayEnhancementService" # maybe only disable for desktops??
  "DispBrokerDesktopSvc",
  "lltdsvc",
  "wlpasvc",
  "TokenBroker",
  # "WinHttpAutoProxySvc", # can't be disabled??
  "CDPSvc",
  "CDPUserSvc"
)

ForEach ($svc in $svcsToDisable) {
  sc.exe stop $svc
  sc.exe config $svc start= disabled
}

If ($svcDel -eq $true) {  # Final cleanup of tracking services
  Set-Location "C:\Windows\System32"
  $files = (
    "dmwappushsvc.dll",		# Device Management Wireless Application Protocol (WAP) Push message Routing Service
    "diagtrack.dll", 		  # Connected User Experiences and Telemetry
    "InventorySvc.dll",		# Microsoft Compatibility Inventory Service
    "DiagSvcs",				    # Microsoft (R) Diagnostics Hub Standard Collector Runtime
    "OneDriveSetup.exe"	  # Microsoft OneDrive installer
  )

  ForEach ($file in $files) {
    If (Test-Location $file) {
      takeown.exe /f $file
      icacls.exe $file /grant everyone:f
      Remove-Item $file -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}

# -------------------------------------------------------------------------------------------- #
# Stage 6: Removal of optional features and capabilities

#clear-host
Write-Host "Stage 5 of debloat finished."
Write-Host "Starting stage 6 of debloat: removal of optional features and capabilities..."

If ($featsAndCapabs -eq $true) {
  $optionalFeatures = (
    # "NetFx3",                               # .NET Framework 3.5 (includes .NET 2.0 and 3.0)    # NOTE: probably keep this installed
    "NetFx4-AdvSrvs",                         # .NET Framework 4.8 Advanced Services
    "DirectoryServices-ADAM-Client",          # Active Directory Lightweight Directory Services
    "Containers",                             # Containers                                        # NOTE: needed for things like Docker
    "DataCenterBridging",                     # Data Center Bridging
    "Client-DeviceLockdown",                  # Device Lockdown
    "HostGuardian",                           # Guarded Host
    "Microsoft-Hyper-V-All",                  # Hyper-V
    "IIS-WebServerRole",                      # Internet Information Services
    "IIS-HostableWebCore",                    # internet Information Services Hostable Web Core
    "LegacyComponents",                       # Legacy Components
    "MediaPlayback",                          # Media Features
    "MSMQ-Container",                         # Message Queuing (MSMQ) Activation
    "Windows-Defender-ApplicationGuard",      # Microsoft Defender Application Guard
    # "Printing-PrintToPDFServices-Features", # Microsoft Print to PDF
    "Printing-XPSServices-Features",          # Microsoft XPS Document Writer
    "MultiPoint-Connector",                   # MultiPoint Connector
    "Printing-Foundation-Features",           # Print and Document Services
    "MSRDC-Infrastructure",                   # Remote Differential Compression API Support
    "ServicesForNFS-ClientOnly",              # Services for NFS
    "SimpleTCP",                              # Simple TCPIP services (i.e. echo, daytime, etc)
    "SMB1Protocol",                           # SMB 1.0/CIFS File Sharing Support
    "SmbDirect",                              # SMB Direct
    "TelnetClient",                           # Telnet Client
    "TFTP",                                   # TFTP Client
    "VirtualMachinePlatform",                 # Virtual Machine Platform
    "HypervisorPlatform",                     # Windows Hypervisor Platform
    "Windows-Identity-Foundation",            # Windows Identity Foundation 3.5
    "MicrosoftWindowsPowerShellv2Root",       # Windows PowerShell 2.0
    "WAS-WindowsActivationService",           # Windows Process Activation Service
    "Client-ProjFS",                          # Windows Projected File System
    "Containers-DisposableClientVM",          # Windows Sandbox
    "Microsoft-Windows-Subsystem-Linux",      # Windows Subsystem for Linux
    "TIFFIFilter",                            # Windows TIFF IFilter
    "WorkFolders-Client"                      # Work Folders Client
  )

  ForEach ($feature in $optionalFeatures) {
    Disable-WindowsOptionalFeature -Online -FeatureName $feature -Remove -NoRestart
  }

  $capabilities = (
    "Microsoft.Windows.WordPad~~~~0.0.1.0",
    "Browser.InternetExplorer~~~~0.0.11.0",
    "MathRecognizer~~~~0.0.1.0",
    "Microsoft.Windows.PowerShell.ISE~~~~0.0.1.0",
    "Hello.Face.20134~~~~0.0.1.0",
    "Media.WindowsMediaPlayer~~~~0.0.12.0",
    "App.StepsRecorder~~~~0.0.1.0"
  )

  ForEach ($capability in $capabilities) {
    Remove-WindowsCapability -Name $capability -Online
  }
}

# -------------------------------------------------------------------------------------------- #
# Final cleanup and restart
$files = (  
  "xaml.zip",
  "vclibs.appx",
  "appinstaller.msixbundle",
  "epsetup.exe",
  "exploit_protection.xml",
  "edge_removal.bat"
)

ForEach ($file in $files) {
  If (Test-Location $file) {
    Remove-Item $env:temp\$file -Recurse -Force -ErrorAction SilentlyContinue
  }
}

Write-Host "Finished debloating Windows."

If ($restart -eq $false) {
  Write-Host "Restarting your PC is strongly advised."
} ElseIf ($restart -eq $true) {
  shutdown -r -t 0
}