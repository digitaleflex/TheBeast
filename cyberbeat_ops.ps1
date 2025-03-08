# CyberBeast Optimization & Security Pack - Mode Extrême
# Version 3.0 - Edition Warfare
# Auteur : Eurin HASH
# Encodage : UTF-8

# Modules requis
$requiredModules = @(
    "PSWindowsUpdate",
    "PowerShellGet",
    "SecurityFever"
)

# Nouvelles variables globales
$script:isGamingMode = $false
$script:isDevMode = $false
$script:isCyberSecMode = $false
$script:performanceProfile = "EXTREME"

# Variables de contrôle de pause
$script:isPaused = $false
$script:pauseEvent = New-Object System.Threading.ManualResetEvent($false)

# Configuration initiale et gestion d'erreurs
$ErrorActionPreference = "Stop"
$global:errorCount = 0
$global:warningCount = 0
$script:totalSteps = 0
$script:currentStep = 0

# Configuration des variables globales
$date = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$scriptRoot = $PSScriptRoot
$logFile = "$env:USERPROFILE\Desktop\Cyberbeast_Logs_$date.txt"
$backupFolder = "$env:USERPROFILE\Desktop\Cyberbeast_Backup_$date"
$systemDrive = $env:SystemDrive
$configFile = Join-Path $scriptRoot "config.json"

# Création du dossier de sauvegarde
New-Item -ItemType Directory -Path $backupFolder -Force | Out-Null

# Fonction d'installation des modules
Function Install-RequiredModules {
    Write-Log "Vérification des modules requis..." "INFO"
    foreach ($module in $requiredModules) {
        if (!(Get-Module -ListAvailable -Name $module)) {
            try {
                Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser
                Write-Log "Module $module installé avec succès" "SUCCESS"
            } catch {
                Write-Log "Erreur lors de l'installation du module $module" "ERROR"
            }
        }
    }
}

# Fonction de gestion d'erreur améliorée
Function Handle-Error {
    param(
        [string]$Operation,
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )
    $global:errorCount++
    Write-Log "ERREUR lors de $Operation : $($ErrorRecord.Exception.Message)" "ERROR"
    if ($global:errorCount -gt 5) {
        Write-Log "Trop d'erreurs détectées. Arrêt du script pour sécurité." "ERROR"
        if (Test-Path $backupFolder) {
            Restore-Settings $backupFolder
        }
        exit 1
    }
}

# Fonction de journalisation améliorée
Function Write-Log {
    Param (
        [string]$message,
        [string]$type = "INFO"
    )
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$type] - $message"
    Add-Content -Path $logFile -Value $logMessage -Encoding UTF8
    Switch ($type) {
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        default { Write-Host $logMessage }
    }
}

# Fonction de vérification de l'intégrité système
Function Test-SystemIntegrity {
    Write-Log "Vérification de l'intégrité système..." "INFO"
    try {
        $sfc = Start-Process "sfc.exe" -ArgumentList "/verifyonly" -Wait -PassThru -WindowStyle Hidden
        if ($sfc.ExitCode -ne 0) {
            Write-Log "Problèmes d'intégrité système détectés" "WARNING"
            return $false
        }
        Write-Log "Intégrité système OK" "SUCCESS"
        return $true
    } catch {
        Write-Log "Erreur lors de la vérification système : $_" "ERROR"
        return $false
    }
}

# Fonction de vérification de la connectivité réseau
Function Test-NetworkConnectivity {
    $networkTests = @(
        @{Host="8.8.8.8"; Description="Connectivité Internet"},
        @{Host=$env:COMPUTERNAME; Description="Réseau local"}
    )
    
    Write-Log "Vérification de la connectivité réseau..." "INFO"
    foreach ($test in $networkTests) {
        if (Test-Connection -ComputerName $test.Host -Count 1 -Quiet) {
            Write-Log "$($test.Description) : OK" "SUCCESS"
        } else {
            Write-Log "$($test.Description) : ÉCHEC" "WARNING"
            $global:warningCount++
        }
    }
}

# Fonction de surveillance des ressources
Function Monitor-SystemResources {
    param([scriptblock]$Operation)
    try {
        $startCPU = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue
        $startRAM = (Get-Counter '\Memory\Available MBytes').CounterSamples.CookedValue
        
        & $Operation
        
        $endCPU = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue
        $endRAM = (Get-Counter '\Memory\Available MBytes').CounterSamples.CookedValue
        
        Write-Log "Impact sur les ressources :" "INFO"
        Write-Log "CPU: $([math]::Round($endCPU - $startCPU, 2))% | RAM: $([math]::Round(($startRAM - $endRAM)/1024, 2))GB" "INFO"
    } catch {
        Handle-Error "surveillance des ressources" $_
    }
}

# Fonction de création de point de restauration
Function Create-SystemRestore {
    param([string]$Description)
    try {
        $date = Get-Date -Format "yyyy-MM-dd_HH-mm"
        Enable-ComputerRestore -Drive $systemDrive -ErrorAction Stop
        Checkpoint-Computer -Description "CyberBeast Backup - $Description - $date" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        Write-Log "Point de restauration créé : $Description" "SUCCESS"
        return $true
    } catch {
        Write-Log "Impossible de créer le point de restauration : $_" "ERROR"
        return $false
    }
}

# Fonction de restauration des paramètres
Function Restore-Settings {
    param([string]$BackupPath)
    Write-Log "Tentative de restauration des paramètres..." "WARNING"
    if (Test-Path $BackupPath) {
        Get-ChildItem -Path $BackupPath -Filter "*.reg" | ForEach-Object {
            try {
                reg import $_.FullName 2>$null
                Write-Log "Restauration réussie : $($_.Name)" "SUCCESS"
            } catch {
                Write-Log "Échec de restauration : $($_.Name)" "ERROR"
            }
        }
    } else {
        Write-Log "Dossier de sauvegarde non trouvé : $BackupPath" "ERROR"
    }
}

# Fonction d'affichage du menu de pause
Function Show-PauseMenu {
    Write-Host "`n=== Menu de Pause ===" -ForegroundColor Cyan
    Write-Host "1. Reprendre l'analyse" -ForegroundColor Green
    Write-Host "2. Voir la progression actuelle" -ForegroundColor Yellow
    Write-Host "3. Voir les statistiques" -ForegroundColor Yellow
    Write-Host "4. Annuler l'analyse" -ForegroundColor Red
    Write-Host "===================`n" -ForegroundColor Cyan
    
    $choice = Read-Host "Choisissez une option (1-4)"
    switch ($choice) {
        "1" { Toggle-PauseResume }
        "2" { 
            Write-Host "`nProgression actuelle :" -ForegroundColor Cyan
            Write-Host "Étape : $script:currentStep sur $script:totalSteps" -ForegroundColor Yellow
            Write-Host "Pourcentage : $([math]::Round(($script:currentStep / $script:totalSteps) * 100, 2))%" -ForegroundColor Yellow
            Show-PauseMenu
        }
        "3" {
            Write-Host "`nStatistiques actuelles :" -ForegroundColor Cyan
            Write-Host "Erreurs : $global:errorCount" -ForegroundColor $(if ($global:errorCount -gt 0) { "Red" } else { "Green" })
            Write-Host "Avertissements : $global:warningCount" -ForegroundColor $(if ($global:warningCount -gt 0) { "Yellow" } else { "Green" })
            Write-Host "Temps écoulé : $([math]::Round(((Get-Date) - (Get-Date $date)).TotalMinutes, 2)) minutes" -ForegroundColor Yellow
            Show-PauseMenu
        }
        "4" {
            $confirm = Read-Host "Êtes-vous sûr de vouloir annuler l'analyse ? (O/N)"
            if ($confirm -eq "O") {
                Write-Log "Analyse annulée par l'utilisateur" "WARNING"
                exit
            } else {
                Show-PauseMenu
            }
        }
        default { Show-PauseMenu }
    }
}

# Fonction de vérification de pause
Function Check-Pause {
    if ($script:isPaused) {
        $script:pauseEvent.WaitOne()
    }
}

# Gestionnaire d'événements pour la touche P
$null = Register-ObjectEvent -InputObject ([System.Console]) -EventName CancelKeyPress -Action {
    if ($_.SourceEventArgs.SpecialKey -eq 'P') {
        Toggle-PauseResume
    }
}

# Fonction de vérification de la compatibilité Windows
Function Test-WindowsCompatibility {
    $osInfo = Get-WmiObject Win32_OperatingSystem
    $osVersion = [Version]$osInfo.Version
    $osName = $osInfo.Caption

    Write-Log "Vérification de la compatibilité Windows..." "INFO"
    Write-Log "Système détecté : $osName" "INFO"

    if ($osVersion -lt [Version]"10.0") {
        Write-Log "Ce script nécessite Windows 10 ou supérieur" "ERROR"
        return $false
    }

    # Vérification spécifique pour Windows 11
    if ($osVersion -ge [Version]"10.0.22000") {
        Write-Log "Windows 11 détecté - Mode de compatibilité activé" "INFO"
        # Ajustements spécifiques pour Windows 11
        $script:isWindows11 = $true
    } else {
        Write-Log "Windows 10 détecté" "INFO"
        $script:isWindows11 = $false
    }

    return $true
}

# Fonction d'analyse avec pause
Function Start-AnalysisWithPause {
    param(
        [scriptblock]$AnalysisBlock,
        [string]$CurrentOperation
    )
    
    Write-Host "`nAppuyez sur 'P' pour mettre en pause/reprendre l'analyse" -ForegroundColor Cyan
    Write-Host "Opération en cours : $CurrentOperation" -ForegroundColor Yellow
    
    try {
        Check-Pause
        & $AnalysisBlock
    } catch {
        Handle-Error "analyse avec pause" $_
    }
}

# Fonction de sauvegarde du registre
Function Backup-Registry {
    param($keyPath, $backupName)
    try {
        $backupFile = Join-Path $backupFolder "$backupName.reg"
        reg export $keyPath $backupFile /y | Out-Null
        Write-Log "Sauvegarde de $keyPath créée : $backupFile" "INFO"
    } catch {
        Write-Log "Erreur lors de la sauvegarde de $keyPath : $_" "ERROR"
    }
}

# Fonction de vérification de l'espace disque
Function Test-DiskSpace {
    $freeSpace = (Get-PSDrive $systemDrive[0]).Free / 1GB
    if ($freeSpace -lt 10) {
        Write-Log "Espace disque insuffisant (${freeSpace:N2} Go). Minimum requis : 10 Go" "ERROR"
        return $false
    }
    return $true
}

# Fonction d'optimisation du mode Gaming
Function Optimize-GamingMode {
    Write-Log "Activation du mode Gaming extrême..." "INFO"
    try {
        # Priorité CPU pour les jeux
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Value 6
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -Value 8
        
        # Optimisations NVIDIA/AMD
        if (Get-WmiObject -Class Win32_VideoController | Where-Object { $_.Name -match "NVIDIA|AMD" }) {
            # NVIDIA Optimizations
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Value 2
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "PerfLevelSrc" -Value 8888
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "PowerMizerEnable" -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "PowerMizerLevel" -Value 1
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "PowerMizerLevelAC" -Value 1
        }

        # Optimisation DX12 et WDDM
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "DpiMapIommuContiguous" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "TdrLevel" -Value 0

        # Optimisation mémoire pour le gaming
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Value 0
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Value 1

        # Optimisation réseau pour le gaming
        $netAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        foreach ($adapter in $netAdapters) {
            Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "*FlowControl" -RegistryValue 0
            Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "*InterruptModeration" -RegistryValue 0
            Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "*PriorityVLANTag" -RegistryValue 3
            Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "*SpeedDuplex" -RegistryValue 0
        }

        # Optimisation audio
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Value 0xffffffff
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Value 0

        Write-Log "Mode Gaming activé avec succès" "SUCCESS"
    } catch {
        Handle-Error "configuration gaming" $_
    }
}

# Fonction d'optimisation pour le développement
Function Optimize-DevelopmentMode {
    Write-Log "Configuration du mode Développement..." "INFO"
    try {
        # Configuration WSL2 et Docker optimisée
        Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart
        
        # Optimisation Visual Studio et IDE
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -Name "EnableCpuOptimizations" -Value 1
        
        # Configuration mémoire pour développement
        $totalRam = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB
        $swapSize = [Math]::Round($totalRam * 2)
        
        # Optimisation du système de fichiers
        fsutil behavior set DisableLastAccess 1
        fsutil behavior set EncryptPagingFile 0
        fsutil behavior set DisableDeleteNotify 0
        
        # Configuration des variables d'environnement
        [System.Environment]::SetEnvironmentVariable("DOTNET_GCHeapCount", "8", [System.EnvironmentVariableTarget]::Machine)
        [System.Environment]::SetEnvironmentVariable("DOTNET_GCHighMemPercent", "90", [System.EnvironmentVariableTarget]::Machine)
        
        # Optimisation Git
        git config --system core.preloadindex true
        git config --system core.fscache true
        git config --system gc.auto 256
        
        # Configuration antivirus pour exclure les dossiers de développement
        Add-MpPreference -ExclusionPath "$env:USERPROFILE\source"
        Add-MpPreference -ExclusionPath "C:\Program Files\Docker"
        Add-MpPreference -ExclusionPath "$env:LOCALAPPDATA\Temp\Npm"
        
        Write-Log "Mode Développement activé avec succès" "SUCCESS"
    } catch {
        Handle-Error "configuration développement" $_
    }
}

# Fonction d'optimisation pour la cybersécurité
Function Optimize-CyberSecMode {
    Write-Log "Activation du mode Cybersécurité..." "INFO"
    try {
        # Configuration avancée du pare-feu
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
        
        # Activation des fonctionnalités de sécurité avancées
        Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart
        
        # Configuration de la stratégie de sécurité
        secedit /configure /cfg %windir%\inf\defltbase.inf /db defltbase.sdb /verbose
        
        # Renforcement du protocole SMB
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
        Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
        
        # Configuration des journaux de sécurité
        wevtutil sl Security /ms:4194304
        wevtutil sl Application /ms:4194304
        wevtutil sl System /ms:4194304
        
        # Configuration avancée de Windows Defender
        Set-MpPreference -DisableRealtimeMonitoring $false
        Set-MpPreference -DisableIOAVProtection $false
        Set-MpPreference -DisableScriptScanning $false
        Set-MpPreference -SubmitSamplesConsent 2
        Set-MpPreference -MAPSReporting Advanced
        Set-MpPreference -PUAProtection Enabled
        
        # Configuration réseau sécurisée
        netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
        netsh advfirewall firewall add rule name="Block_RemoteRegistry" dir=in action=block service="RemoteRegistry" enable=yes
        netsh advfirewall firewall add rule name="Block_RemoteDesktop" dir=in action=block service="TermService" enable=yes
        
        Write-Log "Mode Cybersécurité activé avec succès" "SUCCESS"
    } catch {
        Handle-Error "configuration cybersécurité" $_
    }
}

# Fonction d'optimisation extrême du système
Function Optimize-SystemExtreme {
    Write-Log "Application des optimisations extrêmes..." "INFO"
    try {
        # Désactivation des services non essentiels
        $servicesToDisable = @(
            "DiagTrack", "dmwappushservice", "WSearch", "SysMain",
            "WerSvc", "WbioSrvc", "ShellHWDetection", "TabletInputService"
        )
        foreach ($service in $servicesToDisable) {
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
        }

        # Optimisation du registre
        $registryOptimizations = @{
            "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" = @{
                "LargeSystemCache" = 1
                "IoPageLockLimit" = 983040
            }
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" = @{
                "NetworkThrottlingIndex" = 4294967295
                "SystemResponsiveness" = 0
            }
        }

        foreach ($path in $registryOptimizations.Keys) {
            foreach ($name in $registryOptimizations[$path].Keys) {
                Set-ItemProperty -Path $path -Name $name -Value $registryOptimizations[$path][$name]
            }
        }

        # Configuration mémoire extrême
        $ram = Get-WmiObject Win32_ComputerSystem
        $totalRam = [Math]::Round($ram.TotalPhysicalMemory / 1GB)
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "IoPageLockLimit" -Value ($totalRam * 1024)
        
        # Optimisation du processeur
        $processorOptimizations = @{
            "ProcessorScheduling" = 38
            "ProcessorThrottling" = 0
            "ProcessorPriorityControl" = 1
        }
        foreach ($opt in $processorOptimizations.Keys) {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name $opt -Value $processorOptimizations[$opt]
        }

        Write-Log "Optimisations extrêmes appliquées avec succès" "SUCCESS"
    } catch {
        Handle-Error "optimisation extrême" $_
    }
}

# Fonction d'optimisation pour le streaming
Function Optimize-StreamingMode {
    Write-Log "Configuration du mode Streaming..." "INFO"
    try {
        # Optimisation OBS/Streamlabs
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Value 0xffffffff
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Value 0
        
        # Configuration des priorités
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Affinity" -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Background Only" -Value "False"
        
        # Optimisation de la bande passante
        netsh int tcp set global autotuninglevel=normal
        netsh int tcp set global chimney=enabled
        netsh int tcp set global dca=enabled
        
        Write-Log "Mode Streaming activé avec succès" "SUCCESS"
    } catch {
        Handle-Error "configuration streaming" $_
    }
}

# Fonction d'optimisation pour le cloud computing
Function Optimize-CloudMode {
    Write-Log "Configuration du mode Cloud Computing..." "INFO"
    try {
        # Optimisation des connexions distantes
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpMaxDataRetransmissions" -Value 3
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnablePMTUDiscovery" -Value 1
        
        # Configuration des conteneurs
        Enable-WindowsOptionalFeature -Online -FeatureName Containers -All -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart
        
        Write-Log "Mode Cloud Computing activé avec succès" "SUCCESS"
    } catch {
        Handle-Error "configuration cloud" $_
    }
}

# Fonction d'optimisation pour la création
Function Optimize-CreativeMode {
    Write-Log "Configuration du mode Créatif..." "INFO"
    try {
        # Optimisation pour les logiciels de création
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Value 0xffffffff
        
        # Configuration du cache
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Value 1
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Value 0
        
        Write-Log "Mode Créatif activé avec succès" "SUCCESS"
    } catch {
        Handle-Error "configuration créative" $_
    }
}

# Fonction d'optimisation pour le serveur
Function Optimize-ServerMode {
    Write-Log "Configuration du mode Serveur..." "INFO"
    try {
        # Configuration IIS/Web
        Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole -All -NoRestart
        
        # Optimisation réseau serveur
        Set-NetTCPSetting -SettingName InternetCustom -AutoTuningLevelLocal Normal
        Set-NetTCPSetting -SettingName InternetCustom -ScalingHeuristics Disabled
        
        # Sécurité renforcée
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
        
        Write-Log "Mode Serveur activé avec succès" "SUCCESS"
    } catch {
        Handle-Error "configuration serveur" $_
    }
}

# Modification du menu principal pour inclure les nouveaux modes
Function Show-MainMenu {
    Write-Host "`n=== CyberBeast Warfare Edition ===" -ForegroundColor Cyan
    Write-Host "1. Mode Gaming (Optimisation pour les jeux)" -ForegroundColor Green
    Write-Host "2. Mode Développement (IDE, Compilation, VM)" -ForegroundColor Yellow
    Write-Host "3. Mode Cybersécurité (Pentesting, Analyse)" -ForegroundColor Red
    Write-Host "4. Mode Streaming (OBS, Diffusion)" -ForegroundColor Blue
    Write-Host "5. Mode Cloud (Azure, AWS, GCP)" -ForegroundColor Gray
    Write-Host "6. Mode Créatif (Adobe, 3D)" -ForegroundColor Magenta
    Write-Host "7. Mode Serveur (Web, DB)" -ForegroundColor DarkYellow
    Write-Host "8. Optimisation Extrême (Tous les modes)" -ForegroundColor DarkRed
    Write-Host "9. Quitter" -ForegroundColor Gray
    Write-Host "================================`n" -ForegroundColor Cyan

    $choice = Read-Host "Choisissez votre mode d'optimisation (1-9)"
    switch ($choice) {
        "1" { 
            $script:isGamingMode = $true
            Optimize-GamingMode
        }
        "2" { 
            $script:isDevMode = $true
            Optimize-DevelopmentMode
        }
        "3" { 
            $script:isCyberSecMode = $true
            Optimize-CyberSecMode
        }
        "4" {
            Optimize-StreamingMode
        }
        "5" {
            Optimize-CloudMode
        }
        "6" {
            Optimize-CreativeMode
        }
        "7" {
            Optimize-ServerMode
        }
        "8" { 
            $script:isGamingMode = $true
            $script:isDevMode = $true
            $script:isCyberSecMode = $true
            Optimize-SystemExtreme
            Optimize-GamingMode
            Optimize-DevelopmentMode
            Optimize-CyberSecMode
            Optimize-StreamingMode
            Optimize-CloudMode
            Optimize-CreativeMode
            Optimize-ServerMode
        }
        "9" { exit }
        default { Show-MainMenu }
    }
}

# Fonction de basculement pause/reprise
Function Toggle-PauseResume {
    $script:isPaused = -not $script:isPaused
    if ($script:isPaused) {
        Write-Log "Script mis en pause" "WARNING"
        $script:pauseEvent.Reset()
    } else {
        Write-Log "Script repris" "SUCCESS"
        $script:pauseEvent.Set()
    }
}

# Fonction d'affichage de la progression
Function Show-Progress {
    param(
        [int]$Percent,
        [string]$Status
    )
    Write-Progress -Activity "CyberBeast Optimization" -Status $Status -PercentComplete $Percent
}

# Fonction de mise à jour de la progression
Function Update-Progress {
    param([string]$Status)
    $script:currentStep++
    $percent = [math]::Round(($script:currentStep / $script:totalSteps) * 100)
    Show-Progress -Percent $percent -Status $Status
}

# Fonction d'analyse système
Function Analyze-System {
    $analysis = @{
        CPU = @{
            Usage = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue
            Temperature = Get-WmiObject MSAcpi_ThermalZoneTemperature -Namespace "root/wmi"
        }
        Memory = @{
            Available = (Get-Counter '\Memory\Available MBytes').CounterSamples.CookedValue
            Total = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1MB
        }
        Disk = @{
            FreeSpace = (Get-PSDrive $systemDrive[0]).Free / 1GB
            TotalSpace = (Get-PSDrive $systemDrive[0]).Used / 1GB + (Get-PSDrive $systemDrive[0]).Free / 1GB
        }
        Network = @{
            Adapters = Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object Name, InterfaceDescription
            Connections = Get-NetTCPConnection | Group-Object State | Select-Object Name, Count
        }
    }
    return $analysis
}

# Initialisation de l'analyse système initiale
$systemAnalysis = Analyze-System

Write-Log "Démarrage de l'optimisation et sécurisation du système" "INFO"
Install-RequiredModules

# Vérification de l'espace disque
if (-not (Test-DiskSpace)) {
    Write-Log "Arrêt du script : espace disque insuffisant" "ERROR"
    exit 1
}

# Création des points de restauration
Write-Log "Création d'un point de restauration..." "INFO"
try {
    Enable-ComputerRestore -Drive $systemDrive
    Checkpoint-Computer -Description "Cyberbeast Optimization Backup" -RestorePointType "MODIFY_SETTINGS"
} catch {
    Write-Log "Erreur lors de la création du point de restauration : $_" "ERROR"
}

Try {
    if (-not (Test-WindowsCompatibility)) {
        exit 1
    }

    # Surveillance des ressources avec support de pause
    Monitor-SystemResources {
        Start-AnalysisWithPause {
            # 1. Optimisation CPU et RAM
            Write-Log "Optimisation du CPU et de la RAM..." "INFO"
            Show-Progress -Percent 0 -Status "Configuration CPU/RAM"
            
            try {
                Check-Pause # Vérification de pause avant chaque étape majeure
                
                # Sauvegarde des paramètres actuels
                Backup-Registry "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "MemoryManagement"
                Update-Progress "Sauvegarde des paramètres"
                
                Check-Pause
                # Configuration de SuperFetch selon le type de disque et la version Windows
                $systemDrive = Get-PhysicalDisk | Where-Object { $_.DeviceId -eq 0 }
                if ($systemDrive.MediaType -eq "SSD" -or $script:isWindows11) {
                    Set-Service SysMain -StartupType Disabled
                    Write-Log "SuperFetch désactivé (SSD ou Windows 11 détecté)" "INFO"
                } else {
                    Set-Service SysMain -StartupType Automatic
                    Write-Log "SuperFetch activé (HDD détecté)" "INFO"
                }
                Update-Progress "Configuration SuperFetch"
                
                # Autres optimisations...
            } catch {
                Handle-Error "configuration CPU/RAM" $_
            }
            
            # Continuer avec les autres sections en ajoutant Check-Pause aux points appropriés...
        }
    }

    Show-Progress -Percent 100 -Status "Optimisation terminée"
    Write-Host "`n"
    Write-Log "Optimisation et sécurisation terminées avec succès" "SUCCESS"
    
    # Création d'un point de restauration final
    Create-SystemRestore "Après optimisation"
    
    Write-Log "Un redémarrage est recommandé pour appliquer tous les changements" "WARNING"

} Catch {
    Handle-Error "processus principal" $_
    Write-Log "Le script a rencontré une erreur. Tentative de restauration..." "WARNING"
    Restore-Settings $backupFolder
} Finally {
    # Nettoyage des événements
    Get-EventSubscriber | Unregister-Event
}

# Génération du rapport final de comparaison
Write-Log "Génération du rapport de comparaison..." "INFO"
$finalAnalysis = Analyze-System
$comparisonReport = "$env:USERPROFILE\Desktop\Cyberbeast_Optimization_Comparison_$date.txt"

"=== Rapport de comparaison des optimisations ===" | Out-File $comparisonReport
"Date: $(Get-Date)" | Out-File $comparisonReport -Append
"" | Out-File $comparisonReport -Append

"=== Avant optimisation ===" | Out-File $comparisonReport -Append
$systemAnalysis | ConvertTo-Json -Depth 5 | Out-File $comparisonReport -Append
"" | Out-File $comparisonReport -Append

"=== Après optimisation ===" | Out-File $comparisonReport -Append
$finalAnalysis | ConvertTo-Json -Depth 5 | Out-File $comparisonReport -Append

Write-Log "Rapport de comparaison généré : $comparisonReport" "SUCCESS"

# Statistiques finales
Write-Log "=== Statistiques d'exécution ===" "INFO"
Write-Log "Erreurs rencontrées : $global:errorCount" "INFO"
Write-Log "Avertissements : $global:warningCount" "INFO"
Write-Log "Temps d'exécution total : $([math]::Round(((Get-Date) - (Get-Date $date)).TotalMinutes, 2)) minutes" "INFO"

# Demande de redémarrage
$restart = Read-Host "Voulez-vous redemarrer maintenant ? (O/N)"
if ($restart -eq "O") {
    Write-Log "Redémarrage du système..." "INFO"
    Restart-Computer -Force
} else {
    Write-Log "N'oubliez pas de redémarrer votre système pour appliquer tous les changements" "WARNING"
}
