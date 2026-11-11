 =====================================================================
 README / W-WORLD INJECTION RECIPES (mirror of inject.sh for Linux M-worlds)
 ---------------------------------------------------------------------
 Baseline first, ALWAYS: snapshot the clean VM before injecting.

 W01 firewall off ........ netsh advfirewall set allprofiles state off
 W02 weak password pol ... net accounts /minpwlen:0 /maxpwage:unlimited
 W03 extra admin ......... Add-LocalGroupMember -Group Administrators
                                  -Member "backdoor01"  (create user first)
 W04 passwordless user ... New-LocalUser pawn -NoPassword
 W05 UAC off ............. reg add "HKLM\SOFTWARE\Microsoft\Windows\
                            CurrentVersion\Policies\System" `
                            /v EnableLUA /t REG_DWORD /d 0 /f
 W06 autologon ........... reg add "HKLM\SOFTWARE\Microsoft\Windows NT\
                            CurrentVersion\Winlogon" `
                            /v AutoAdminLogon /t REG_SZ /d 1 /f
 W07 SMBv1 on ............ Server: Install-WindowsFeature FS-SMB1
                            Client: dism /online /enable-feature
                                  /featurename:SMB1Protocol
 W08 Defender RTP off .... Set-MpPreference -DisableRealtimeMonitoring $true
 W09 RDP exposed ......... reg add "HKLM\SYSTEM\CurrentControlSet\
                            Control\Terminal Server" `
                            /v fDenyTSConnections /t REG_DWORD /d 0 /f
                           (+ enable the service)
 W10 telnet server ....... Install-WindowsFeature Telnet-Server
                           (server SKUs; no client equivalent)

 Rollback between worlds: qm rollback <vmid> <snapshot> on Proxmox —
 never stack W-worlds on top of each other unless deliberately creating
 combo samples.

 EXECUTION: unsigned script -> run with
   powershell -ExecutionPolicy Bypass -File .\collect.ps1 ...

 VERIFICATION (key-set parity with a Linux snapshot):
   $win = (Get-ChildItem ..\dataset\win*.json | Sort LastWriteTime |
           Select -Last 1 | Get-Content | ConvertFrom-Json).features_ml
   $lin = (Get-Content <linux_snapshot.json> | ConvertFrom-Json).features_ml
   $wk = $win.PSObject.Properties.Name | Where {$_ -notlike 'risk_win_*'}
   Compare-Object ($lin.PSObject.Properties.Name) $wk   # expect empty
 =====================================================================

