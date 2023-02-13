<#
    THIS SCRIPT GENERATES AN APP IDENTITY IN THE AZURE TENANT AND ADDS BOTH A CERT AND SECRET TO THE CERT
    ALL OPERATIONS ARE OUTPUTTED TO THE CONSOLE, THE CERT IS PLACED IN Cert:\localmachine\my
    NOTE: REQUIRES TENANT GLOBAL ADMIN PERMISSIONS
#>

$aadAppName = ""
$selfSignedCertPlainPassword = ""
$monthsUntilAppCredExpires
$azureSubscriptionName = ""
$azureTenantId = ""

Connect-AzAccount -TenantId $azureTenantId -SubscriptionName $azureSubscriptionName -Scope Process
Set-AzContext -Tenant $azureTenantId -Subscription $azureSubscriptionName -Scope Process
$azContext = Get-AzContext 
Connect-AzureAD -TenantId $azContext.Tenant -AccountId $azContext.Account.Id 

function Create-SelfSignedCertificate {
    [cmdletbinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $certificateName, 
        [Parameter(Mandatory = $true, Position = 1)]
        [string] $selfSignedCertPlainPassword,
        [Parameter(Mandatory = $true, Position = 2)]
        [string] $certPath, 
        [Parameter(Mandatory = $true, Position = 3)]
        [string] $certPathCer, 
        [Parameter(Mandatory = $true, Position = 4)]
        [string] $selfSignedCertNoOfMonthsUntilExpired
    )

    try {
        $selfSignedCert = New-SelfSignedCertificate -DnsName $certificateName -CertStoreLocation cert:\LocalMachine\My `
            -KeyExportPolicy Exportable -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
            -NotAfter (Get-Date).AddMonths($selfSignedCertNoOfMonthsUntilExpired) -HashAlgorithm SHA256
        $CertPassword = ConvertTo-SecureString $selfSignedCertPlainPassword -AsPlainText -Force
        Export-PfxCertificate -Cert ("Cert:\localmachine\my\" + $selfSignedCert.Thumbprint) -FilePath $certPath `
            -Password $CertPassword -Force | Write-Verbose
        Export-Certificate -Cert ("Cert:\localmachine\my\" + $selfSignedCert.Thumbprint) `
            -FilePath $certPathCer -Type CERT | Write-Verbose    

        Write-Host ""
        Write-Host "**********************************************" -ForegroundColor DarkYellow
        Write-Host "'$certificateName' Self-Signed Certificate Information:" -ForegroundColor DarkYellow
        Write-Host "  Cert Name: $certificateName"
        Write-Host "  Cert Thumbprint: $($selfSignedCert.Thumbprint)"
        Write-Host "  Cert Expire Date: $($selfSignedCert.NotAfter)"
        Write-Host "  Install Path: Cert:\localmachine\my\"
        Write-Host "PFX exported to '$certPath'"
        Write-Host "Cert exported to '$certPathCer'"
        Write-Host "--------------------------------------------------------------------------------------------------------------" -ForegroundColor Yellow
        Write-Host "NOTE: It is recommended that the .pfx and .cer files are moved to a secure location " -ForegroundColor Yellow 
        Write-Host "--------------------------------------------------------------------------------------------------------------" -ForegroundColor Yellow
        Write-Host "**********************************************" -ForegroundColor DarkYellow
        return $selfSignedCert
    }
    catch {
        Write-Host "Cert creation failed: $($_.Exception.Message)" -ForegroundColor Red
        return null
    }
    
    
}

try {
    $aadAppObj = Get-AzADApplication -DisplayName $aadAppName
        
    if ($null -eq $aadAppObj) {   
        $aadAppSvcPrincCertName = $aadAppName + "-cert"                
        $aadAppSvcPrincPfxCertPath = Join-Path $env:TEMP ($aadAppSvcPrincCertName + ".pfx")
        $aadAppSvcPrincCerCertPath = Join-Path $env:TEMP ($aadAppSvcPrincCertName + ".cer")                
        $aadAppSvcPrincCert = Create-SelfSignedCertificate -certificateName $aadAppSvcPrincCertName `
            -selfSignedCertPlainPassword $selfSignedCertPlainPassword `
            -certPath $aadAppSvcPrincPfxCertPath -certPathCer $aadAppSvcPrincCerCertPath `
            -selfSignedCertNoOfMonthsUntilExpired $monthsUntilAppCredExpires                
        if ($null -eq $aadAppSvcPrincCert) { return; }
        $pfxCert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 `
            -ArgumentList @($aadAppSvcPrincPfxCertPath, $selfSignedCertPlainPassword)
        $certKeyValue = [System.Convert]::ToBase64String($pfxCert.GetRawCertData())            
        $uriAppId = (New-Guid).Guid
        $aadAppObj = New-AzADApplication -DisplayName $aadAppName `
            -HomePage ("http://" + $aadAppName) -IdentifierUris ("api://$azureTenantID/$uriAppId")

        Start-Sleep -Seconds 15
        $aadAppApplicationId = $aadAppObj.AppId.ToString()    
        $aadAppObjectId = $aadAppObj.Id.ToString()    
        $appCertCredential = New-AzADAppCredential -ApplicationId $aadAppApplicationId `
            -CertValue $certKeyValue -StartDate $pfxCert.NotBefore -EndDate $pfxCert.NotAfter
        Start-Sleep -Seconds 20
        $appSecretCredentials = New-AzureADApplicationPasswordCredential -ObjectId $aadAppObjectId `
            -CustomKeyIdentifier "AppAccessKey" -StartDate (Get-Date) -EndDate (Get-Date).AddMonths($MonthsUntilAppCredExpires)
        $aadAppSecret = $appSecretCredentials.Value                
        $setSP = Set-AzureADApplication -ObjectId $aadAppObjectId -PasswordCredentials $appSecretCredentials                            
        
        Write-Host ""
        Write-Host "**********************************************" -ForegroundColor DarkYellow
        Write-Host "Application '$aadAppName' Information:" -ForegroundColor DarkYellow
        Write-Host "  App Object Id: $aadAppObjectId"
        Write-Host "  App Client Id: $aadAppApplicationId"
        Write-Host "  App Password: $aadAppSecret" 
        Write-Host "**********************************************" -ForegroundColor DarkYellow

    }
}
catch {
    Write-Host "Provisioning failed: $($_.Exception.Message)" -ForegroundColor Red
}

    

