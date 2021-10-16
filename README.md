# NO LONGER MAINTAINED

# Gorecon - lightweight Reconnaissance Tool

**Gorecon is a lightweight Reconnaissance Tool , which might make your recon process a bit more easy 
(It is still in its Beta state )**


# Main Features
`1  - [+] Dns Lookup `

`2  - [+] Whois Lookup`

`3  - [+] Nmap scan` 

`4  - [+] Zone Transfer Lookup `

`5  - [+]  Shared DNS server lookup`

`6  - [+] Web Scrapper `

`7  - [+] Reverse DNS lookup`

`8  - [+] Subnet calculator`

`9  - [+] Admin panel finder (with Screenshots)`

`10 - [+] Directory Bruteforce (with Screenshots)`

`11 - [+] Configuration Files Finder`

`12 - [+] HTTP Header Information`

`13 - [+] GeoIp Lookup`

`14 - [+] Find/Analyze Content Management System (CMS)`

`15 - [+] Email Hunter (find emails of the company)`

`16 - [+] Use Rapid7 Open Data's Project Sonar for Finding Subdomains)`

`17 - [+] Use Virustotal API for Finding subdomains`

`18 - [+] Use Threatcrowd's API for Finding subdomains`

`19 - [+] Run All scans`

# Compatibility
**Gorecon is still in its beta state , It works fine though. 
It will run on anything that has Go compiler installed ,
Tested on  : Windows,Linux**

# Installation 
**Gorecon can be easily installed by following the below mentioned steps : 
Note : Before installing gorecon make sure you have Go installed on your machine**

**1 - run the following commands :**

`go get "github.com/devanshbatham/gorecon"`

`go get "github.com/fatih/color"`

`go get "github.com/likexian/whois-go"`

`go get "github.com/gocolly/colly"`

**2 - Run  :**
`go run gorecon.go --url example.com`

# Usage 
**Gorecon can be used in the following ways :**

`go run gorecon.go --url example.com`

`go run gorecon.go -url example.com`

#run all scans without user input 
`echo "19\n y"| ./gorecon --url example.com` 

# Files 
`paths.txt - for directory Bruteforce`

`conf.txt  - for configuration file Bruteforce`

`read.txt  - for admin panel Bruteforce`

# Contact 
**want to collabarate or chat in private? DM me [My twitter : @devanshwolf!](http://twitter.com/devanshwolf)**

# Contribution & License

**You can contribute in following ways:**

    * Report bugs
    * Give suggestions to make it better
    * Fix issues & submit a pull request
    * Suggest New features 
    
# Wanna show support for the tool ? 
**I will be more than happy if you will show some love for Animals by donating to [Animal Aid Unlimited](https://animalaidunlimited.org/)**
**,Animal Aid Unlimited saves animals through street animal rescue, spay/neuter and education.
Their mission is dedicated to the day when all living beings are treated with compassion and love.** :sparkles:

**PS : I know the code is dirty , :P**
