using namespace System
using namespace System.IO
using namespace System.Collections.Generic
using namespace Microsoft.PowerShell.Commands

Function Get-LrtDnsQueryLogs {
    <#
    .SYNOPSIS
        Pull logs from BlueCat

    .DESCRIPTION
        Returns a total count of logged DNS queries for a given siteName. 
        You can use optional filters, such as record key (search for records older or newer than the specified key), start time, and end time.

    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    

    .PARAMETER siteId	- List of strings (optional)
        The ID of the site for which you want to query logs. 
        If no site ID is provided, an error is returned. 
        If there is no site with that ID, an empty list is returned.

    .PARAMETER batchSize - string (optional)
        The maximum number of records to return. If this isn't included, the response will be limited to 400 entries.
        Note: The maximum configurable batchSize is 10000.

    .PARAMETER key - string (optional)
        The key is the record ID of the DNS Query Log record for which you want to receive older or newer records.

    .PARAMETER order - string (optional)
        Specify whether to retrieve results in DESC (most recent records first) or ASC (oldest records first) order. 
        If this isn't included, the records will be listed in descending order.

    .PARAMETER startTime - string (optional)
        To filter results for a specific time period, including the start time, in milliseconds since the Unix Epoch.

    .PARAMETER endTime	- string (optional)
        To filter results for a specific time period, in milliseconds since the Unix Epoch. The filter results will only include DNS queries with a timestamp leess than the endTime value.

    .PARAMETER hasMatchedPolicy	- string (optional)
        If hasMatchedPolicy is true then only DNS queries matching policies will be displayed.

    .PARAMETER sourceIp	- list of strings (optional)
        Filters results for the specified source IP address(es).

    .PARAMETER queryType - list of strings (optional)
        The query record type you want to search for.

    .PARAMETER queryName - list of strings (optional)
        The domain name you want to search for queries on.

    .PARAMETER policyAction	- list of strings (optional)
        If one or more policy actions are provided, then only policies matching the actions are returned. Valid actions are allow, block, redirect, and monitor.

    .PARAMETER policyName - list of strings (optional)
        If a policy name is provided, then only policies matching the name are returned.

    .PARAMETER policyId	- list of strings (optional)
        If a policy ID is provided, then only policies matching the ID are returned.

    .PARAMETER threatType - list of strings (optional)
        Returns queries that match the specified threat type. Valid threat types are DGA and DNS_TUNNELING.

    .PARAMETER threatIndicator - list of strings (optional)
        Returns queries that match the specified threat indicator. Valid threat indicators are ENTROPY, UNIQUE_CHARACTER, EXCEEDING_LENGTH, UNCOMMON_QUERY_TYPE, VOLUMETRIC_TUNNELING, SUSPECT_DNS, and SUSPECT_TLD.

    .PARAMETER responseCode	- list of strings (optional)
        The response code of the DNS query.

    .PARAMETER protocol	- list of strings (optional)
        The protocol of the DNS query (usually UDP or TCP).

    .PARAMETER namespaceId - list of strings (optional)
        The ID of namespaces a DNS query was queried against.

    .PARAMETER latencyFrom	- string (optional)
        Returns DNS queries with latencies greater than or equal to this value (in milliseconds).

    .PARAMETER latencyTo - string (optional)
        Returns DNS queries with latencies less than or equal to this value (in milliseconds).

    .PARAMETER responseIp - string (optional)
        Returns the DNS events resolving to either of the specified IPv4 and/or IPv6 address(es). Must be valid IPv4 or IPv6 address(es).

    
    .OUTPUTS

        Time: Unix time (in milliseconds) when the DNS query was made. (This is the request time, not the response time or logging time.)
        Source: The IP address of the client making the DNS query.
        Site: The site name of the service point handling the query.
        Query: The domain name being queried.
        QueryType: The query type.
        Response: The response code (for example NXDOMAIN, NOERROR or SERVFAIL).
        ID: An identifier that can be passed to key in subsequent requests (used for paging through lots of data)
        Action Taken: If no policy was matched, this will be "query-response", otherwise this will be either block,redirect, or monitor
        Matched Policies: List of policy IDs and names that matched the given query
        The number of entries in the list depends on the number of queries within specified period. The list returned may be empty.

        Authority: The authority assigned to the DNS query.
        QueryProtocol: The protocol of the DNS query (usually UDP or TCP).
        Threats: The list of possible threats detected during the query analysis.
        QueriedNamespaces: The list of namespaces the DNS query was queried against.
        Latency: The latency (in milliseconds) of the DNS query.

        200 OK
            Content-Type: application/JSON
            [
            {
            "time":1588863296043,
            "source":"197.210.227.230",
            "siteId":"91d9e73b-c5ce-4f92-a419-5d421e8fef25",
            "query":"VERSION.BIND.",
            "queryType":"TXT",
            "actionTaken":"query-response",
            "response":"NOERROR",
            "id":"1588863296043BF913F410812953C6909E622C4702754",
            "matchedPolicies": [
            ],
            "answers": [
                {
                    "domainName":"VERSION.BIND.",
                    "recordType":"TXT",
                    "parsed":true,
                    "rData":"1.0.0"
                }
            ],
            "authority":[
            ],
            "queryProtocol":"UDP",
            "threats":[
            ],
            "queriedNamespaces": [
            {
                    "id":"9bba84cc-00eb-4a6a-985b-b9cadb9de93a",
                    "name":"Umbrella"
            },
            ....
            ],
            "latency":0
            }
        
    .EXAMPLE
        
        PS C:\> Get-LrCases -tags alpha

            id                      : 56C2007B-4E8D-41C8-95C8-4F91346EC727
            number                  : 1
        externalId              :
        dateCreated             : 2020-07-16T16:46:48.3522746Z
        dateUpdated             : 2020-07-16T16:53:46.0262639Z
        dateClosed              :
        owner                   : @{number=2; name=LRTools; disabled=False}
        lastUpdatedBy           : @{number=2; name=LRTools; disabled=False}
        name                    : Alpha Case
        status                  : @{name=Created; number=1}
        priority                : 4
        dueDate                 : 2020-07-17T16:46:48.3362732Z
        resolution              :
        resolutionDateUpdated   :                           
        resolutionLastUpdatedBy :
        summary                 : Alpha case is the first case created through API.
        entity                  : @{number=-100; name=Global Entity; fullName=Global Entity}
        collaborators           : {@{number=2; name=LRTools; disabled=False}}
        tags                    : {@{number=2; text=Alpha}}

        id                      : E66A5D03-412F-43AB-B9B7-0459055827AF
        number                  : 2
        externalId              :
        dateCreated             : 2020-07-16T16:47:46.0395837Z
        dateUpdated             : 2020-07-16T16:56:27.8545625Z
        dateClosed              :
        owner                   : @{number=2; name=LRTools; disabled=False}
        lastUpdatedBy           : @{number=2; name=LRTools; disabled=False}
        name                    : Mock case
        status                  : @{name=Created; number=1}
        priority                : 5
        dueDate                 : 2020-10-20T14:22:11Z
        resolution              :
        resolutionDateUpdated   :
        resolutionLastUpdatedBy :
        summary                 : Mock case summary for automation validation.
        entity                  : @{number=-100; name=Global Entity; fullName=Global Entity}
        collaborators           : {@{number=2; name=LRTools; disabled=False}}
        tags                    : {@{number=2; text=Alpha}}
    .EXAMPLE
        PS C:\> Get-LrCases -Name "Mock"

        id                      : E66A5D03-412F-43AB-B9B7-0459055827AF
        number                  : 2
        externalId              :
        dateCreated             : 2020-07-16T16:47:46.0395837Z
        dateUpdated             : 2020-07-16T16:56:27.8545625Z
        dateClosed              :
        owner                   : @{number=2; name=LRTools; disabled=False}
        lastUpdatedBy           : @{number=2; name=LRTools; disabled=False}
        name                    : Mock case
        status                  : @{name=Created; number=1}
        priority                : 5
        dueDate                 : 2020-10-20T14:22:11Z
        resolution              :
        resolutionDateUpdated   :
        resolutionLastUpdatedBy :
        summary                 : Mock case summary for automation validation.
        entity                  : @{number=-100; name=Global Entity; fullName=Global Entity}
        collaborators           : {@{number=2; name=LRTools; disabled=False}}
        tags                    : {@{number=2; text=Alpha}}
    .EXAMPLE
        PS C:\> Get-LrCases -Name "Mock" -Exact
        
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>


    [CmdletBinding()]
    Param(

        #region: Query Parameters ___________________________________________________________

        [Parameter(Mandatory = $false, Position = 0)]
        [string[]] $siteId,
        
        [Parameter(Mandatory = $false, Position = 1)]
        [string] $batchSize,

        [Parameter(Mandatory = $false, Position = 2)]
        [string] $key,

        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateSet("ASC","DESC")]    
        [string] $order = "DESC",

        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateScript({[datetime]$origin = '1970-01-01 00:00:00'
                        if ([datetime]$origin.AddMilliseconds($_) -lt (get-date).ToUniversalTime()) {
                        $true
                        }
        })]
        [string] $starttime,

        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateScript({[datetime]$origin = '1970-01-01 00:00:00'
                        if ([datetime]$origin.AddMilliseconds($_) -lt (get-date).ToUniversalTime()) {
                        $true   
                    }
               }
            )
        ]
        [string] $endtime,

        [Parameter(Mandatory = $false, Position = 6)]
        [ValidateSet("True","False")] 
        [string] $hasMatchedPolicy,

        [Parameter(Mandatory = $false, Position = 7)]
        [ValidateNotNull()]
        [string[]] $SourceIp,

        [Parameter(Mandatory = $false, Position = 8)]
        [string[]] $queryType,
        
        [Parameter(Mandatory = $false, Position = 9)]
        [string[]] $queryName,

        [Parameter(Mandatory = $false, Position = 10)]
        [ValidateSet("Block","Allow","Redirect","Monitor")] 
        [string[]] $policyAction,

        [Parameter(Mandatory = $false,Position = 11)]
        [string[]] $policyId,

        [Parameter(Mandatory = $false,Position = 12)]
        [ValidateSet("DGA","DNS_TUNNELING")] 
        [string[]] $threatType,

        [Parameter(Mandatory = $false,Position = 13)]
        [ValidateSet(
            "ENTROPY",
            "UNIQUE_CHARACTER",
            "EXCEEDING_LENGTH",
            "UNCOMMON_QUERY_TYPE",
            "VOLUMETRIC_TUNNELING",
            "SUSPECT_DNS",
            "SUSPECT_TLD"
            )]
        [string[]] $threatIndicator,

        [Parameter(Mandatory = $false,Position = 14)]
        [string[]] $responseCode,

        [Parameter(Mandatory = $false, Position = 15)]
        [string[]] $protocol,

        [Parameter(Mandatory = $false, Position = 16)]
        [string[]] $namespaceId,

        [Parameter(Mandatory = $false, Position = 17)]
        [string] $latencyFrom,

        [Parameter(Mandatory = $false, Position = 18)]
        [string] $latencyTo,

        [Parameter(Mandatory = $false, Position = 19)]
        [string[]] $responseIp,

        [Parameter(Mandatory = $false, Position = 20)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey

        #endregion
        )

    Begin {
        #region: Setup_______________________________________________________________________
        $Me = $MyInvocation.MyCommand.Name
        $BaseUrl = $LrtConfig.BlueCat.DNSEdgeInstance
        $clientid = $LrtConfig.BlueCat.$clientid
        $clientsecret = $LrtConfig.BlueCat.$clientsecret
        $catAuthUrl = "https://$BaseUrl/api/authentication/token"
        $authbody = @{
            grantType = "ClientCredentials";
            clientCredentials = @{
            clientId = $clientid;
            clientSecret = $clientsecret
            } 
        } | ConvertTo-Json -Depth 9
        $Request = Invoke-RestMethod -Method "POST" -Uri $catAuthUrl -Body $authbody -ContentType "application/json"
        $token = $Request.accessToken

        
        # HTTP Method
        $Method = $HttpMethod.Get

        # Enable self-signed certificates and Tls1.2
        Enable-TrustAllCertsPolicy
        #endregion
    }
    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Value                 =   $List
            Code                  =   $Null
            Type                  =   $null
            Note                  =   $null
        }
  
        $QueryParams = [Dictionary[string,string]]::new()

        # Format
        $QueryParams.Add("format", $Format)
        $QueryParams.Add("siteId", $siteId)
        $QueryParams.Add("batchSize", $batchSize)
        $QueryParams.Add("key", $key)
        $QueryParams.Add("order", $order)
        $QueryParams.Add("starttime", $starttime)
        $QueryParams.Add("endtime", $endtime)
        $QueryParams.Add("hasMatchedPolicy", $hasMatchedPolicy)
        $QueryParams.Add("sourceIp", $SourceIp)
        $QueryParams.Add("queryType", $queryType)
        $QueryParams.Add("queryName", $queryName)
        $QueryParams.Add("policyAction", $policyAction)
        $QueryParams.Add("policyId", $policyId)
        $QueryParams.Add("threatType", $threatType)
        $QueryParams.Add("threatIndicator", $threatIndicator)
        $QueryParams.Add("responseCode", $responseCode)
        $QueryParams.Add("protocol", $protocol)
        $QueryParams.Add("namespaceId", $namespaceId)
        $QueryParams.Add("latencyFrom", $latencyFrom)
        $QueryParams.Add("latencyTo", $latencyTo)
        $QueryParams.Add("responseIp", $responseIp)
 
        if ($QueryParams.Count -gt 0) {
            $QueryString = $QueryParams | ConvertTo-QueryString
            Write-Verbose "[$Me]: QueryString is [$QueryString]"
        }

        # Define Search URL
        
        #region: Process Request Headers_____________________________________________________
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $token")
        $Headers.Add("Content-Type","application/json")
        $queryUrl = "https://$BaseUrl/v3/api/dnsQueryLogs?" + $QueryString
        Write-Verbose "[$Me]: RequestUrl: $RequestUrl"

        Try {
            $Results = Invoke-RestMethod -Method $Method -Uri $queryUrl -Headers $header
        }
        catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            $ErrorObject.Error = $true
            $ErrorObject.Type = "System.Net.WebException"
            $ErrorObject.Code = $($Err.statusCode)
            $ErrorObject.Note = $($Err.message)
            return $ErrorObject
        }


        $ResultsList = @($Results | ConvertFrom-Csv | Select-Object @{Name="Time";Expression={[int64]$_.time}},@{Name="Source";Expression={[string]$_.source}},@{Name="Site ID";Expression={[string]$_.siteId}},@{Name="Query";Expression={[string]$_.query}},@{Name="Query Type";Expression={[string]$_.queryType}},@{Name="Action Taken";Expression={[string]$_.actionTaken}},@{Name="Response";Expression={[string]$_.response}},@{Name="ID";Expression={[string]$_.id}},@{Name="Matched Policies";Expression={[string]$_.matchedPolicies}},@{Name="Answers";Expression={[string]$_.answers}},@{Name="Authority";Expression={[string]$_.authority}},@{Name="Query Protocol";Expression={[string]$_.queryProtocol}},@{Name="Threats";Expression={[string]$_.threats}},@{Name="Queried Namespaces";Expression={[string]$_.queriedNamespaces}},@{Name="Latency";Expression={[string]$_.latency}})

         # Return Values only as an array or all results as object
        if ($ValuesOnly) {
            Return ,$ResultsList.Name
        } else {
            Return $ResultsList
        }
    }

    End { }
}