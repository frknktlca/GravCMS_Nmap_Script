description = [[
GravCMS Unauthenticated Arbitrary YAML Write/Update leads to Code Execution
 CVE-2021-21425
Manual inspection:
# timeout 15 curl -k -s -m 10 'https://<target>/admin' | grep 'action="/'
References:
https://nvd.nist.gov/vuln/detail/CVE-2021-21425
]]

---
-- @usage
-- nmap -p443 --script grav_cms.nse <target>
-- @output
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



author = "Furkan Kutluca"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"vuln", "exploit"}

local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"

portrule = shortport.http
action = function(host, port)

    local vuln = {
        title = "GravCMS (CVE-2021-21425)",
        state = vulns.STATE.NOT_VULN,
        IDS = { CVE = 'CVE-2021-21425' },
                description = [[
GravCMS Unauthenticated Arbitrary YAML Write/Update leads to Code Execution]],

                references = {
           'https://pentest.blog/unexpected-journey-7-gravcms-unauthenticated-arbitrary-yaml-write-update-leads-to-code-execution/'
       },
       dates = {
           disclosure = {year = '2021', month = '03', day = '19'},
       },

    }

    local report = vulns.Report:new(SCRIPT_NAME, host, port)

    local uri = "/admin"

    local response = http.post(host, port, uri)

    if ( response.status == 200 ) then

    local title = string.match(response.body, 'action="/')

        if (title == 'action="/') then
                vuln.state = vulns.STATE.EXPLOIT
        else
                vuln.state = vulns.STATE.NOT_VULN
        end

    end

    return report:make_output (vuln)
end
