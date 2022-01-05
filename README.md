# AS2Go-Setup-Domain-Controller
Files to prepare the AS2GO | Domain Controller Setup. AS2Go is an acronym for Attack Scenario To Go. 

Find more information here in my blog post [AS2Go | Lab Setup | Domain Controller](https://herrhozi.com/2022/01/04/as2go-lab-setup-domain-controller/). 

## Quick Start Guide
Open a Admin PowerShell terminal from the Windows command.

The following command will automatically create a set of users based on the current date.
```PowerShell
AS2GO-create-users.ps1
```

The following command will automatically create a set of users based on the current date and time 
```PowerShell
AS2GO-create-users.ps1 -Shortname n
```

The following command will automatically create a set of users based on an predefined name
```PowerShell
AS2GO-create-users.ps1 -Shortname HerrHozi
```

![image](https://user-images.githubusercontent.com/96825160/148137999-90d65163-29d8-488e-8be7-0922c23762c0.png)
