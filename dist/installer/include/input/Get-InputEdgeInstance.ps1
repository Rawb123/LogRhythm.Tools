using namespace System

Function Get-InputEdgeInstance {
    <#
    .SYNOPSIS
        Determine if a user entered a valid EDGE Instance.
    .PARAMETER Value
        String to evaluate as an EDGE Instance.
    .EXAMPLE
        PS C:\> Get-InputEdgeInstance "api-<DNS.edge.url>.edge.bluec.at",
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Value
    )


    # Return object 
    $Return = [PSCustomObject]@{
        Value = $null
        Valid = $false
    }


    # Parsing OAuth2 URL for TenantId: Group 4 would contain the TenantId/Guid
        # Group #  Description          Example
        # -------  -----------          ----------------
        # Group 1: Full match           "https://login.microsoftonline.com/{GUID}/oauth2/token"
        # Group 2: Only if Https        "s"
        # Group 3: Host                 "login.microsoftonline.com"
    #--># Group 4: Tenant Id            {GUID}
        # Group 5: Remainder of URL     "/oauth2/token"
    
    $Match = "api-[a-zA-Z0-9]+\.edge\.bluec\.at"

    # Parse the old value for TenantId
    $MatchSuccess = $Match.Match($Value)


    # If we could not parse a valid Url + TenantId, then source data is bad.
    if (! $MatchSuccess.Success) {
        Write-Host "    [!] Warning: Syntax does not appear to be correct. " -ForegroundColor Red
        Write-Host "    Update this field directly in the configuration." -ForegroundColor Red
        # set valid to true because user input won't help change it.
        $Return.Valid = $true
        return $Return
    }
}