# GravCMS_Nmap_Script
It is a nmap script for GravCMS vulnerability (CVE-2021-21425)

USAGE

-- nmap -p443 --script grav_cms.nse <target>

-- PORT    STATE SERVICE

-- 443/tcp open  https

-- | grav_cms: 

-- |   VULNERABLE:

-- |   GravCMS (CVE-2021-21425)

-- |     State: VULNERABLE (Exploitable)

-- |     IDs:  CVE:CVE-2021-21425

-- |       GravCMS Unauthenticated Arbitrary YAML Write/Update leads to Code Execution

-- |     Disclosure date: 2021-03-19

-- |     References:

-- |       https://pentest.blog/unexpected-journey-7-gravcms-unauthenticated-arbitrary-yaml-write-update-leads-to-code-execution/

-- |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-21425
