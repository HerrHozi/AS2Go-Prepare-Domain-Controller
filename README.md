# AS2Go-Setup-Domain-Controller
Files to prepare the AS2Go | Domain Controller Setup. AS2Go is an acronym for Attack Scenario To Go. 

Find more information here in my blog post [AS2Go | Lab Setup | Domain Controller](https://herrhozi.com/as2go-lab-setup-1-3-dc/). 

## Quick Start Guide
Open a PowerShell Shell as Administrator

### STEP #1 - Create the AS2Go OU Structure

Run the following command to create the required OU structure and AD Groups.
```PowerShell
New-AS2GoOus.ps1 
```
![New-AS2GoOUs](https://user-images.githubusercontent.com/96825160/198332993-21f8cd80-513c-4fe5-9a9c-6aa590aa51c6.gif)


### STEP #2 Create a subset of dummy users

The following command will automatically create a set of users based on the current date.
```PowerShell
New-AS2GoUsers.ps1 
```

The following command will automatically create a set of users based on the current date and time 
```PowerShell
New-AS2GoUsers -Shortname n
```

The following command will automatically create a set of users based on an predefined name
```PowerShell
New-AS2GoUsers -Shortname HerrHozi
```
![New-AS2GoUsers](https://user-images.githubusercontent.com/96825160/198341525-9ce6c7bc-3d91-4e6e-b231-0c0a699dc767.gif)
