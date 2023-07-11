# Detecting TeamsPhisher tool and MS Teams Phishing [Malware delivery] - Defender for Enpoint logs

## Sources
https://posts.inthecyber.com/leveraging-microsoft-teams-for-initial-access-42beb07f12c4 

https://labs.jumpsec.com/advisory-idor-in-microsoft-teams-allows-for-external-tenants-to-introduce-malware/

https://github.com/Octoberfest7/TeamsPhisher

## Topic intro
* This query was be able to detect files sent from external domains using MS Teams.
* Detections of TeamsPhisher activity and manual non enterprise external MS Teams accounts phishing.
* This query can't detect MS Teams phishing URLs (lack of logs with this info or logs after sampling like CloudAppEvents)
* FileRenamed used instead of FileCreated because MDE is sampling FileCreated (not all file creations are logged)


## Detection description
* Detection is based on Defender for Endpoint logs, DeviceProcessEvents table
* Correlation of ActionType ProcessCreated and FileRenamed
* Whitelisting of common domains present in organisation
* Query is not optimised with KQL best practices 
  

### KQL

**KQL query:**

```C#
// Baseline of common SharePoint domains observerd in organisation/Allow list
let SenderSharepointDomainBaseline = datatable (SenderSharepointDomainName:string)[
    "test.sharepoint.com" // 
];
DeviceProcessEvents
| where InitiatingProcessFileName == "Teams.exe" and InitiatingProcessCommandLine !contains "https://teams.microsoft.com/l/meetup-join"
| parse-where ProcessCommandLine with * "--single-argument " OneDriveSuspiciousURL
//| where OneDriveSuspiciousURL !contains "ORGTENANTNAME.sharepoint.com" //whitelisting organisation sharepoint pages
//| where OneDriveSuspiciousURL !contains "ORGTENANTNAME-my.sharepoint.com" 
| where OneDriveSuspiciousURL !contains "statics.teams.cdn."
| where OneDriveSuspiciousURL contains "sharepoint.com" // enterprise sharepoint with Azure AD, used by TeamsPhisher tool 
  or OneDriveSuspiciousURL startswith "https://1drv.ms" // private sharepoint, phishing from non enterprise accounts like gmail etc.
| extend URLParsed = parse_url(OneDriveSuspiciousURL)
| extend SenderSharepointDomain = tostring(URLParsed.Host)
| where SenderSharepointDomain !in (SenderSharepointDomainBaseline)
| extend MSTeamsClickTime=TimeGenerated
| join (DeviceFileEvents
    | where isnotempty(SHA256)
    | where ActionType == "FileRenamed"
    and PreviousFileName endswith ".crdownload"
    | extend FileDownloadTime=TimeGenerated
    )
    on DeviceId and $left.InitiatingProcessAccountSid == $right.RequestAccountSid and InitiatingProcessAccountUpn and $left.FileName == $right.InitiatingProcessFileName
    | where (FileDownloadTime - MSTeamsClickTime) between (0min .. 2min)
| extend
    MSTeamsClickTime = TimeGenerated, 
    BrowserOneDriveDownloadTime = TimeGenerated1,
    InitiatingParentProcessFileName = InitiatingProcessFileName,
    InitiatingProcessFileName = InitiatingProcessFileName1,
    FilePath = FolderPath1,
    DownloadedFile = FileName1 
| project
    MSTeamsClickTime,
    BrowserOneDriveDownloadTime,
    DeviceName,
    InitiatingProcessAccountUpn,
    InitiatingParentProcessFileName,
    InitiatingProcessFileName,
    OneDriveSuspiciousURL,
    FilePath,
    DownloadedFile
| extend URLParsed = parse_url(OneDriveSuspiciousURL)
| extend SenderSharepointDomain = tostring(URLParsed.Host)
| where SenderSharepointDomain !in (SenderSharepointDomainBaseline)


```


## Query results
![image](https://github.com/turekbar/KQL-for-SOC/assets/139212782/92836c2c-74ee-43f5-918c-05da1428357f)

## Recommendation
* Scheduling setting: Query every 1h, Time range 1h
* Baseline can be created using this query:
```C#
DeviceProcessEvents
| where InitiatingProcessFileName == "Teams.exe" and InitiatingProcessCommandLine !contains "https://teams.microsoft.com/l/meetup-join"
| parse-where ProcessCommandLine with * "--single-argument " OneDriveSuspiciousURL
| where OneDriveSuspiciousURL !contains "statics.teams.cdn."
| where OneDriveSuspiciousURL contains "sharepoint.com" or OneDriveSuspiciousURL startswith "https://1drv.ms"
| extend URLParsed = parse_url(OneDriveSuspiciousURL)
| extend SenderSharepointDomain = tostring(URLParsed.Host)
| summarize count() by SenderSharepointDomain 

```
