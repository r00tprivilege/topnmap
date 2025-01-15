#  NMAP & Its useful cheatsheet
## User manual &amp; top nse scripts of NMAP
---
#### Nmap (“Network Mapper”) is a free and open-source utility for network discovery and security auditing. Many systems and network administrators also find it useful for tasks such as network inventory, managing service upgrade schedules, and monitoring host or service uptime. It uses raw IP packets in novel ways to determine what hosts are available on the network, what services (application name and version) those hosts are offering, what operating systems (and OS versions) they are running, what type of packet filters/firewalls are in use, and dozens of other characteristics.
---
#### Basic Syntax:<br />
#### ``` nmap [Scan Type] [Options] {targe specification} ```
---

#### Default Help Menu
<details><summary>NMAP Default Help</summary>
<p>
  
```lua
Nmap 5.51 ( http://nmap.org )
Usage: nmap [Scan Type(s)] [Options] {target specification}
TARGET SPECIFICATION:
  Can pass hostnames, IP addresses, networks, etc.
  Ex: scanme.nmap.org, 192.168.0.1; 10.0.0-255.1-254
  -iL : Input from list of hosts/networks
  -iR : Choose random targets
  --exclude <host1[,host2][,host3],...>: Exclude hosts/networks
  --excludefile : Exclude list from file
HOST DISCOVERY:
  -sL: List Scan - simply list targets to scan
  -sn: Ping Scan - disable port scan
  -Pn: Treat all hosts as online -- skip host discovery
  -PS/PA/PU/PY[portlist]: TCP SYN/ACK, UDP or SCTP discovery to given ports
  -PE/PP/PM: ICMP echo, timestamp, and netmask request discovery probes
  -PO[protocol list]: IP Protocol Ping
  -n/-R: Never do DNS resolution/Always resolve [default: sometimes]
  --dns-servers <serv1[,serv2],...>: Specify custom DNS servers
  --system-dns: Use OS's DNS resolver
  --traceroute: Trace hop path to each host
SCAN TECHNIQUES:
  -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
  -sU: UDP Scan
  -sN/sF/sX: TCP Null, FIN, and Xmas scans
  --scanflags : Customize TCP scan flags
  -sI : Idle scan
  -sY/sZ: SCTP INIT/COOKIE-ECHO scans
  -sO: IP protocol scan
  -b : FTP bounce scan
PORT SPECIFICATION AND SCAN ORDER:
  -p : Only scan specified ports
    Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9
  -F: Fast mode - Scan fewer ports than the default scan
  -r: Scan ports consecutively - don't randomize
  --top-ports : Scan  most common ports
  --port-ratio : Scan ports more common than 
SERVICE/VERSION DETECTION:
  -sV: Probe open ports to determine service/version info
  --version-intensity : Set from 0 (light) to 9 (try all probes)
  --version-light: Limit to most likely probes (intensity 2)
  --version-all: Try every single probe (intensity 9)
  --version-trace: Show detailed version scan activity (for debugging)
SCRIPT SCAN:
  -sC: equivalent to --script=default
  --script=:  is a comma separated list of
           directories, script-files or script-categories
  --script-args=<n1=v1,[n2=v2,...]>: provide arguments to scripts
  --script-trace: Show all data sent and received
  --script-updatedb: Update the script database.
OS DETECTION:
  -O: Enable OS detection
  --osscan-limit: Limit OS detection to promising targets
  --osscan-guess: Guess OS more aggressively
TIMING AND PERFORMANCE:
  Options which take  are in seconds, or append 'ms' (milliseconds),
  's' (seconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m).
  -T<0-5>: Set timing template (higher is faster)
  --min-hostgroup/max-hostgroup : Parallel host scan group sizes
  --min-parallelism/max-parallelism : Probe parallelization
  --min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout : Specifies
      probe round trip time.
  --max-retries : Caps number of port scan probe retransmissions.
  --host-timeout : Give up on target after this long
  --scan-delay/--max-scan-delay : Adjust delay between probes
  --min-rate : Send packets no slower than  per second
  --max-rate : Send packets no faster than  per second
FIREWALL/IDS EVASION AND SPOOFING:
  -f; --mtu : fragment packets (optionally w/given MTU)
  -D <decoy1,decoy2[,ME],...>: Cloak a scan with decoys
  -S : Spoof source address
  -e : Use specified interface
  -g/--source-port : Use given port number
  --data-length : Append random data to sent packets
  --ip-options : Send packets with specified ip options
  --ttl : Set IP time-to-live field
  --spoof-mac : Spoof your MAC address
  --badsum: Send packets with a bogus TCP/UDP/SCTP checksum
OUTPUT:
  -oN/-oX/-oS/-oG : Output scan in normal, XML, s|: Output in the three major formats at once
  -v: Increase verbosity level (use -vv or more for greater effect)
  -d: Increase debugging level (use -dd or more for greater effect)
  --reason: Display the reason a port is in a particular state
  --open: Only show open (or possibly open) ports
  --packet-trace: Show all packets sent and received
  --iflist: Print host interfaces and routes (for debugging)
  --log-errors: Log errors/warnings to the normal-format output file
  --append-output: Append to rather than clobber specified output files
  --resume : Resume an aborted scan
  --stylesheet <path/URL>: XSL stylesheet to transform XML output to HTML
  --webxml: Reference stylesheet from Nmap.Org for more portable XML
  --no-stylesheet: Prevent associating of XSL stylesheet w/XML output
MISC:
  -6: Enable IPv6 scanning
  -A: Enable OS detection, version detection, script scanning, and traceroute
  --datadir : Specify custom Nmap data file location
  --send-eth/--send-ip: Send using raw ethernet frames or IP packets
  --privileged: Assume that the user is fully privileged
  --unprivileged: Assume the user lacks raw socket privileges
  -V: Print version number
  -h: Print this help summary page.
EXAMPLES:
  nmap -v -A scanme.nmap.org
  nmap -v -sn 192.168.0.0/16 10.0.0.0/8
  nmap -v -iR 10000 -Pn -p 80
```
</p>
</details>


## NSE Scripts:
##### The Nmap Scripting Engine (NSE) is one of Nmap’s most powerful and flexible features. It allows users to write (and share) simple scripts to automate a wide variety of networking tasks. Those scripts are then executed in parallel with the speed and efficiency you expect from Nmap.

---
## 1. dns-brute.nse

##### Attempts to enumerate DNS hostnames by brute force guessing of common subdomains.

```
Categories: intrusive, discovery
Download: https://svn.nmap.org/nmap/scripts/dns-brute.nse
```
<details><summary>dns-brute.nse</summary>
<p>
  
```lua
local coroutine = require "coroutine"
local dns = require "dns"
local io = require "io"
local math = require "math"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local stringaux = require "stringaux"
local table = require "table"
local target = require "target"
local rand = require "rand"

description = [[
Attempts to enumerate DNS hostnames by brute force guessing of common
subdomains. With the <code>dns-brute.srv</code> argument, dns-brute will also
try to enumerate common DNS SRV records.

Wildcard records are listed as "*A" and "*AAAA" for IPv4 and IPv6 respectively.
]]
-- 2011-01-26

---
-- @usage
-- nmap --script dns-brute --script-args dns-brute.domain=foo.com,dns-brute.threads=6,dns-brute.hostlist=./hostfile.txt,newtargets -sS -p 80
-- nmap --script dns-brute www.foo.com
-- @args dns-brute.hostlist The filename of a list of host strings to try.
--                          Defaults to "nselib/data/vhosts-default.lst"
-- @args dns-brute.threads  Thread to use (default 5).
-- @args dns-brute.srv      Perform lookup for SRV records
-- @args dns-brute.srvlist  The filename of a list of SRV records to try.
--                          Defaults to "nselib/data/dns-srv-names"
-- @args dns-brute.domain   Domain name to brute force if no host is specified
--
-- @see dns-nsec3-enum.nse
-- @see dns-ip6-arpa-scan.nse
-- @see dns-nsec-enum.nse
-- @see dns-zone-transfer.nse
--
-- @output
-- Pre-scan script results:
-- | dns-brute:
-- |   DNS Brute-force hostnames
-- |     www.foo.com - 127.0.0.1
-- |     mail.foo.com - 127.0.0.2
-- |     blog.foo.com - 127.0.1.3
-- |     ns1.foo.com - 127.0.0.4
-- |     admin.foo.com - 127.0.0.5
-- |_    *A: 127.0.0.123
--
-- @xmloutput
-- <table key="DNS Brute-force hostnames">
--   <table>
--     <elem key="address">127.0.0.1</elem>
--     <elem key="hostname">www.foo.com</elem>
--   </table>
--   <table>
--     <elem key="address">127.0.0.2</elem>
--     <elem key="hostname">mail.foo.com</elem>
--   </table>
--   <table>
--     <elem key="address">127.0.1.3</elem>
--     <elem key="hostname">blog.foo.com</elem>
--   </table>
--   <table>
--     <elem key="address">127.0.0.4</elem>
--     <elem key="hostname">ns1.foo.com</elem>
--   </table>
--   <table>
--     <elem key="address">127.0.0.5</elem>
--     <elem key="hostname">admin.foo.com</elem>
--   </table>
--   <elem key="*A">127.0.0.123</elem>
-- </table>
-- <table key="SRV results"></table>

author = "Cirrus"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"intrusive", "discovery"}

prerule = function()
  if not stdnse.get_script_args("dns-brute.domain") then
    stdnse.debug1("Skipping '%s' %s, 'dns-brute.domain' argument is missing.", SCRIPT_NAME, SCRIPT_TYPE)
    return false
  end
  return true
end

hostrule = function(host)
  return true
end

local function guess_domain(host)
  local name

  name = stdnse.get_hostname(host)
  if name and name ~= host.ip then
    return string.match(name, "%.([^.]+%..+)%.?$") or string.match(name, "^([^.]+%.[^.]+)%.?$")
  else
    return nil
  end
end

-- Single DNS lookup, returning all results. dtype should be e.g. "A", "AAAA".
local function resolve(host, dtype)
  local status, result = dns.query(host, {dtype=dtype,retAll=true})
  return status and result or false
end

local function array_iter(array, i, j)
  return coroutine.wrap(function ()
    while i <= j do
      coroutine.yield(array[i])
      i = i + 1
    end
  end)
end

local record_mt = {
  __tostring = function(t)
    return ("%s - %s"):format(t.hostname, t.address)
  end
}

local function make_record(hostn, addr)
  local record = { hostname=hostn, address=addr }
  setmetatable(record, record_mt)
  return record
end

local function thread_main(domainname, results, name_iter)
  local condvar = nmap.condvar( results )
  for name in name_iter do
    for _, dtype in ipairs({"A", "AAAA"}) do
      local res = resolve(name..'.'..domainname, dtype)
      if(res) then
        table.sort(res)
        if results["*" .. dtype] ~= res[1] then
          for _,addr in ipairs(res) do
            local hostn = name..'.'..domainname
            if target.ALLOW_NEW_TARGETS then
              stdnse.debug1("Added target: "..hostn)
              local status,err = target.add(hostn)
            end
            stdnse.debug2("Hostname: "..hostn.." IP: "..addr)
            results[#results+1] = make_record(hostn, addr)
          end
        end
      end
    end
  end
  condvar("signal")
end

local function srv_main(domainname, srvresults, srv_iter)
  local condvar = nmap.condvar( srvresults )
  for name in srv_iter do
    local res = resolve(name..'.'..domainname, "SRV")
    if(res) then
      for _,addr in ipairs(res) do
        local hostn = name..'.'..domainname
        addr = stringaux.strsplit(":",addr)
        for _, dtype in ipairs({"A", "AAAA"}) do
          local srvres = resolve(addr[4], dtype)
          if(srvres) then
            for srvhost,srvip in ipairs(srvres) do
              if target.ALLOW_NEW_TARGETS then
                stdnse.debug1("Added target: "..srvip)
                local status,err = target.add(srvip)
              end
              stdnse.debug1("Hostname: "..hostn.." IP: "..srvip)
              srvresults[#srvresults+1] = make_record(hostn, srvip)
            end
          end
        end
      end
    end
  end
  condvar("signal")
end

local function detect_wildcard(domainname, record)
  local rand_host1 = rand.random_alpha(24).."."..domainname
  local rand_host2 = rand.random_alpha(24).."."..domainname
  local res1 = resolve(rand_host1, record)

  stdnse.debug1("Detecting wildcard for \"%s\" records using random hostname \"%s\".", record, rand_host1)
  if res1 then
    stdnse.debug1("Random hostname resolved. Comparing to second random hostname \"%s\".", rand_host2)
    local res2 = resolve(rand_host2, record)
    table.sort(res1)
    table.sort(res2)

    if (res1[1] == res2[1]) then
      stdnse.debug1("Both random hostnames resolved to the same IP. Wildcard detected.")
      return res1[1]
    end
  end

  return nil
end

action = function(host)
  local domainname = stdnse.get_script_args('dns-brute.domain')
  if not domainname then
    domainname = guess_domain(host)
  end

  if not domainname then
    return string.format("Can't guess domain of \"%s\"; use %s.domain script argument.", stdnse.get_hostname(host), SCRIPT_NAME)
  end

  if not nmap.registry.bruteddomains then
    nmap.registry.bruteddomains = {}
  end

  if nmap.registry.bruteddomains[domainname] then
    stdnse.debug1("Skipping already-bruted domain %s", domainname)
    return nil
  end

  nmap.registry.bruteddomains[domainname] = true
  stdnse.debug1("Starting dns-brute at: "..domainname)
  local max_threads = tonumber( stdnse.get_script_args('dns-brute.threads') ) or 5
  local dosrv = stdnse.get_script_args("dns-brute.srv") or false
  stdnse.debug1("THREADS: "..max_threads)
  -- First look for dns-brute.hostlist
  local fileName = stdnse.get_script_args('dns-brute.hostlist')
  -- Check fetchfile locations, then relative paths
  local commFile = (fileName and nmap.fetchfile(fileName)) or fileName
  -- Finally, fall back to vhosts-default.lst
  commFile = commFile or nmap.fetchfile("nselib/data/vhosts-default.lst")
  local hostlist = {}
  if commFile then
    for l in io.lines(commFile) do
      if not l:match("#!comment:") then
        table.insert(hostlist, l)
      end
    end
  else
    stdnse.debug1("Cannot find hostlist file, quitting")
    return
  end

  local threads, results, srvresults = {}, {}, {}
  for _, dtype in ipairs({"A", "AAAA"}) do
    results["*" .. dtype] = detect_wildcard(domainname, dtype)
  end

  local condvar = nmap.condvar( results )
  local i = 1
  local howmany = math.floor(#hostlist/max_threads)+1
  stdnse.debug1("Hosts per thread: "..howmany)
  repeat
    local j = math.min(i+howmany, #hostlist)
    local name_iter = array_iter(hostlist, i, j)
    threads[stdnse.new_thread(thread_main, domainname, results, name_iter)] = true
    i = j+1
  until i > #hostlist
  local done
  -- wait for all threads to finish
  while( not(done) ) do
    done = true
    for thread in pairs(threads) do
      if (coroutine.status(thread) ~= "dead") then done = false end
    end
    if ( not(done) ) then
      condvar("wait")
    end
  end

  if(dosrv) then
    -- First look for dns-brute.srvlist
    fileName = stdnse.get_script_args('dns-brute.srvlist')
    -- Check fetchfile locations, then relative paths
    commFile = (fileName and nmap.fetchfile(fileName)) or fileName
    -- Finally, fall back to dns-srv-names
    commFile = commFile or nmap.fetchfile("nselib/data/dns-srv-names")
    local srvlist = {}
    if commFile then
      for l in io.lines(commFile) do
        if not l:match("#!comment:") then
          table.insert(srvlist, l)
        end
      end

      i = 1
      threads = {}
      howmany = math.floor(#srvlist/max_threads)+1
      condvar = nmap.condvar( srvresults )
      stdnse.debug1("SRV's per thread: "..howmany)
      repeat
        local j = math.min(i+howmany, #srvlist)
        local name_iter = array_iter(srvlist, i, j)
        threads[stdnse.new_thread(srv_main, domainname, srvresults, name_iter)] = true
        i = j+1
      until i > #srvlist
      local done
      -- wait for all threads to finish
      while( not(done) ) do
        done = true
        for thread in pairs(threads) do
          if (coroutine.status(thread) ~= "dead") then done = false end
        end
        if ( not(done) ) then
          condvar("wait")
        end
      end
    else
      stdnse.debug1("Cannot find srvlist file, skipping")
    end
  end

  local response = stdnse.output_table()
  if(#results==0) then
    setmetatable(results, { __tostring = function(t) return "No results." end })
  end
  response["DNS Brute-force hostnames"] = results
  if(dosrv) then
    if(#srvresults==0) then
      setmetatable(srvresults, { __tostring = function(t) return "No results." end })
    end
    response["SRV results"] = srvresults
  end
  return response
end
```
</p>
</details>
----------------------------------------------------

## 2. http-enum.nse

##### Enumerates directories used by popular web applications and servers.

```
Categories: discovery, intrusive, vuln
Download: https://svn.nmap.org/nmap/scripts/http-enum.nse
```
<details><summary>http-enum.nse</summary>
<p>
  
```lua
local _G = require "_G"
local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enumerates directories used by popular web applications and servers.

This parses a fingerprint file that's similar in format to the Nikto Web application
scanner. This script, however, takes it one step further by building in advanced pattern matching as well
as having the ability to identify specific versions of Web applications.

You can also parse a Nikto-formatted database using http-fingerprints.nikto-db-path. This will try to parse
most of the fingerprints defined in nikto's database in real time. More documentation about this in the
nselib/data/http-fingerprints.lua file.

Currently, the database can be found under Nmap's directory in the nselib/data folder. The file is called
http-fingerprints and has a long description of its functionality in the file header.

Many of the finger prints were discovered by me (Ron Bowes), and a number of them are from the Yokoso
project, used with permission from Kevin Johnson (http://seclists.org/nmap-dev/2009/q3/0685.html).

Initially, this script attempts to access two different random files in order to detect servers
that don't return a proper 404 Not Found status. In the event that they return 200 OK, the body
has any non-static-looking data removed (URI, time, etc), and saved. If the two random attempts
return different results, the script aborts (since a 200-looking 404 cannot be distinguished from
an actual 200). This will prevent most false positives.

In addition, if the root folder returns a 301 Moved Permanently or 401 Authentication Required,
this script will also abort. If the root folder has disappeared or requires authentication, there
is little hope of finding anything inside it.

By default, only pages that return 200 OK or 401 Authentication Required are displayed. If the
<code>http-enum.displayall</code> script argument is set, however, then all results will be displayed (except
for 404 Not Found and the status code returned by the random files). Entries in the http-fingerprints
database can specify their own criteria for accepting a page as valid.

]]

---
-- @args http-enum.basepath         The base path to prepend to each request. Leading/trailing slashes are ignored.
-- @args http-enum.displayall       Set this argument to display all status codes that may indicate a valid page, not
--                                  just 200 OK and 401 Authentication Required pages. Although this is more likely
--                                  to find certain hidden folders, it also generates far more false positives.
-- @args http-enum.fingerprintfile  Specify a different file to read fingerprints from.
-- @args http-enum.category         Set to a category (as defined in the fingerprints file). Some options are 'attacks',
--                                  'database', 'general', 'microsoft', 'printer', etc.
-- @args http-fingerprints.nikto-db-path Looks at the given path for nikto database.
--       It then converts the records in nikto's database into our Lua table format
--       and adds them to our current fingerprints if they don't exist already.
--       Unfortunately, our current implementation has some limitations:
--          * It doesn't support records with more than one 'dontmatch' patterns for
--            a probe.
--          * It doesn't support logical AND for the 'match' patterns.
--          * It doesn't support sending additional headers for a probe.
--       That means, if a nikto fingerprint needs one of the above features, it
--       won't be loaded. At the time of writing this, 6546 out of the 6573 Nikto
--       fingerprints are being loaded successfully.  This runtime Nikto fingerprint integration was suggested by Nikto co-author Chris Sullo as described at http://seclists.org/nmap-dev/2013/q4/292
--
-- @output
-- Interesting ports on test.skullsecurity.org (208.81.2.52):
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-enum:
-- |   /icons/: Icons and images
-- |   /images/: Icons and images
-- |   /robots.txt: Robots file
-- |   /sw/auth/login.aspx: Citrix WebTop
-- |   /images/outlook.jpg: Outlook Web Access
-- |   /nfservlets/servlet/SPSRouterServlet/: netForensics
-- |_  /nfservlets/servlet/SPSRouterServlet/: netForensics
--
-- @see http-iis-short-name-brute.nse

author = {"Ron Bowes", "Andrew Orr", "Rob Nicholls"}

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "intrusive", "vuln"}


portrule = shortport.http

-- TODO
-- o Automatically convert HEAD -> GET if the server doesn't support HEAD
-- o Add variables for common extensions, common CGI extensions, etc that expand the probes

-- File extensions (TODO: Implement this)
local cgi_ext = { 'php', 'asp', 'aspx', 'jsp', 'pl', 'cgi' }

local common_ext = { 'php', 'asp', 'aspx', 'jsp', 'pl', 'cgi', 'css', 'js', 'htm', 'html' }

---Convert the filename to backup variations. These can be valuable for a number of reasons.
-- First, because they may not have the same access restrictions as the main version (file.php
-- may run as a script, but file.php.bak or file.php~ might not). And second, the old versions
-- might contain old vulnerabilities
--
-- At the time of the writing, these were all decided by me (Ron Bowes).
local function get_variations(filename)
  local variations = {}

  if(filename == nil or filename == "" or filename == "/") then
    return {}
  end

  local is_directory = (string.sub(filename, #filename, #filename) == "/")
  if(is_directory) then
    filename = string.sub(filename, 1, #filename - 1)
  end

  -- Try some extensions
  table.insert(variations, filename .. ".bak")
  table.insert(variations, filename .. ".1")
  table.insert(variations, filename .. ".tmp")

  -- Strip off the extension, if it has one, and try it all again.
  -- For now, just look for three-character extensions.
  if(string.sub(filename, #filename - 3, #filename - 3) == '.') then
    local bare = string.sub(filename, 1, #filename - 4)
    local extension = string.sub(filename, #filename - 3)

    table.insert(variations, bare .. ".bak")
    table.insert(variations, bare .. ".1")
    table.insert(variations, bare .. ".tmp")
    table.insert(variations, bare .. "_1" .. extension)
    table.insert(variations, bare .. "2" .. extension)
  end


  -- Some Windowsy things
  local onlyname = string.sub(filename, 2)
  -- If the name contains a '/', forget it
  if(string.find(onlyname, "/") == nil) then
    table.insert(variations, "/Copy of " .. onlyname)
    table.insert(variations, "/Copy (2) of " .. onlyname)
    table.insert(variations, "/Copy of Copy of " .. onlyname)

    -- Word/Excel/etc replace the first two characters with '~$', it seems
    table.insert(variations, "/~$" .. string.sub(filename, 4))
  end

  -- Some editors add a '~'
  table.insert(variations, filename .. "~")

  -- Try some directories
  table.insert(variations, "/bak" .. filename)
  table.insert(variations, "/backup" .. filename)
  table.insert(variations, "/backups" .. filename)
  table.insert(variations, "/beta" .. filename)
  table.insert(variations, "/test" .. filename)

  -- If it's a directory, add a '/' after every entry
  if(is_directory) then
    for i, v in ipairs(variations) do
      variations[i] = v .. "/"
    end
  end

  -- Some compressed formats (we don't want a trailing '/' on these, so they go after the loop)
  table.insert(variations, filename .. ".zip")
  table.insert(variations, filename .. ".tar")
  table.insert(variations, filename .. ".tar.gz")
  table.insert(variations, filename .. ".tgz")
  table.insert(variations, filename .. ".tar.bz2")



  return variations
end

-- simplify unlocking the mutex, ensuring we don't try to parse again, and returning an error.
local function bad_prints(mutex, err)
  nmap.registry.http_fingerprints = err
  mutex "done"
  return false, err
end

---Get the list of fingerprints from files. The files are defined in <code>fingerprint_files</code>. If category
-- is non-nil, only choose scripts that are in that category.
--
--@return An array of entries, each of which have a <code>checkdir</code> field, and possibly a <code>checkdesc</code>.
local function get_fingerprints(fingerprint_file, category)
  local entries  = {}
  local i
  local total_count = 0 -- Used for 'limit'

  -- Check if we've already read the file
  local mutex = nmap.mutex("http_fingerprints")
  mutex "lock"
  if nmap.registry.http_fingerprints then
    if type(nmap.registry.http_fingerprints) == "table" then
      stdnse.debug1("Using cached HTTP fingerprints")
      mutex "done"
      return true, nmap.registry.http_fingerprints
    else
      return bad_prints(mutex, nmap.registry.http_fingerprints)
    end
  end

  -- Try and find the file; if it isn't in Nmap's directories, take it as a direct path
  local filename_full = nmap.fetchfile('nselib/data/' .. fingerprint_file)
  if(not(filename_full)) then
    filename_full = fingerprint_file
  end

  stdnse.debug1("Loading fingerprint database: %s", filename_full)
  local env = setmetatable({fingerprints = {}}, {__index = _G})
  local file = loadfile(filename_full, "t", env)
  if(not(file)) then
    stdnse.debug1("Couldn't load configuration file: %s", filename_full)
    return bad_prints(mutex, "Couldn't load fingerprint file: " .. filename_full)
  end

  file()

  local fingerprints = env.fingerprints

  -- Sanity check our file to ensure that all the fields were good. If any are bad, we
  -- stop and don't load the file.
  for i, fingerprint in pairs(fingerprints) do
    -- Make sure we have a valid index
    if(type(i) ~= 'number') then
      return bad_prints(mutex, "The 'fingerprints' table is an array, not a table; all indexes should be numeric")
    end

    -- Make sure they have either a string or a table of probes
    if(not(fingerprint.probes) or
        (type(fingerprint.probes) ~= 'table' and type(fingerprint.probes) ~= 'string') or
        (type(fingerprint.probes) == 'table' and #fingerprint.probes == 0)) then
      return bad_prints(mutex, "Invalid path found for fingerprint " .. i)
    end

    -- Make sure fingerprint.path is a table
    if(type(fingerprint.probes) == 'string') then
      fingerprint.probes = {fingerprint.probes}
    end

    -- Make sure the elements in the probes array are strings or arrays
    for i, probe in pairs(fingerprint.probes) do
      -- Make sure we have a valid index
      if(type(i) ~= 'number') then
        return bad_prints(mutex, "The 'probes' table is an array, not a table; all indexes should be numeric")
      end

      -- Convert the probe to a table if it's a string
      if(type(probe) == 'string') then
        fingerprint.probes[i] = {path=fingerprint.probes[i]}
        probe = fingerprint.probes[i]
      end

      -- Make sure the probes table has a 'path'
      if(not(probe['path'])) then
        return bad_prints(mutex, "The 'probes' table requires each element to have a 'path'.")
      end

      -- If they didn't set a method, set it to 'GET'
      if(not(probe['method'])) then
        probe['method'] = 'GET'
      end

      -- Make sure the method's a string
      if(type(probe['method']) ~= 'string') then
        return bad_prints(mutex, "The 'method' in the probes file has to be a string")
      end
    end

    -- Ensure that matches is an array
    if(type(fingerprint.matches) ~= 'table') then
      return bad_prints(mutex, "'matches' field has to be a table")
    end

    -- Loop through the matches
    for i, match in pairs(fingerprint.matches) do
      -- Make sure we have a valid index
      if(type(i) ~= 'number') then
        return bad_prints(mutex, "The 'matches' table is an array, not a table; all indexes should be numeric")
      end

      -- Check that every element in the table is an array
      if(type(match) ~= 'table') then
        return bad_prints(mutex, "Every element of 'matches' field has to be a table")
      end

      -- Check the output field
      if(match['output'] == nil or type(match['output']) ~= 'string') then
        return bad_prints(mutex, "The 'output' field in 'matches' has to be present and a string")
      end

      -- Check the 'match' and 'dontmatch' fields, if present
      if((match['match'] and type(match['match']) ~= 'string') or (match['dontmatch'] and type(match['dontmatch']) ~= 'string')) then
        return bad_prints(mutex, "The 'match' and 'dontmatch' fields in 'matches' have to be strings, if they exist")
      end

      -- Change blank 'match' strings to '.*' so they match everything
      if(not(match['match']) or match['match'] == '') then
        match['match'] = '(.*)'
      end
    end

    -- Make sure the severity is an integer between 1 and 4. Default it to 1.
    if(fingerprint.severity and (type(fingerprint.severity) ~= 'number' or fingerprint.severity < 1 or fingerprint.severity > 4)) then
      return bad_prints(mutex, "The 'severity' field has to be an integer between 1 and 4")
    elseif not fingerprint.severity then
      fingerprint.severity = 1
    end

    -- Make sure ignore_404 is a boolean. Default it to false.
    if(fingerprint.ignore_404 and type(fingerprint.ignore_404) ~= 'boolean') then
      return bad_prints(mutex, "The 'ignore_404' field has to be a boolean")
    elseif not fingerprint.ignore_404 then
      fingerprint.ignore_404 = false
    end
  end

  -- Make sure we have some fingerprints
  if(#fingerprints == 0) then
    return bad_prints(mutex, "No fingerprints were loaded")
  end

  -- If the user wanted to filter by category, do it
  if(category) then
    local filtered_fingerprints = {}
    for _, fingerprint in pairs(fingerprints) do
      if(fingerprint.category == category) then
        table.insert(filtered_fingerprints, fingerprint)
      end
    end

    fingerprints = filtered_fingerprints

    -- Make sure we still have fingerprints after the category filter
    if(#fingerprints == 0) then
      return bad_prints(mutex, "No fingerprints matched the given category (" .. category .. ")")
    end
  end


  --  -- If the user wants to try variations, add them
  --  if(try_variations) then
  --    -- Get a list of all variations for this directory
  --    local variations = get_variations(entry['checkdir'])
  --
  --    -- Make a copy of the entry for each of them
  --    for _, variation in ipairs(variations) do
  --      new_entry = {}
  --      for k, v in pairs(entry) do
  --        new_entry[k] = v
  --      end
  --      new_entry['checkdesc'] = new_entry['checkdesc'] .. " (variation)"
  --      new_entry['checkdir'] = variation
  --      table.insert(entries, new_entry)
  --      count = count + 1
  --    end
  --  end

  -- Cache the fingerprints for other scripts, so we aren't reading the files every time
  nmap.registry.http_fingerprints = fingerprints
  mutex "done"

  return true, fingerprints
end

action = function(host, port)
  local response = {}

  -- Read the script-args, keeping the old ones for reverse compatibility
  local basepath         = stdnse.get_script_args({'http-enum.basepath',        'path'})         or '/'
  local displayall       = stdnse.get_script_args({'http-enum.displayall',      'displayall'})   or false
  local fingerprint_file = stdnse.get_script_args({'http-enum.fingerprintfile', 'fingerprints'}) or 'http-fingerprints.lua'
  local category         = stdnse.get_script_args('http-enum.category')
  --  local try_variations   = stdnse.get_script_args({'http-enum.tryvariations',   'variations'})   or false
  --  local limit            = tonumber(stdnse.get_script_args({'http-enum.limit', 'limit'})) or -1

  -- Add URLs from external files
  local status, fingerprints = get_fingerprints(fingerprint_file, category)
  if(not(status)) then
    return stdnse.format_output(false, fingerprints)
  end
  stdnse.debug1("Loaded %d fingerprints", #fingerprints)

  -- Identify servers that answer 200 to invalid HTTP requests and exit as these would invalidate the tests
  local status_404, result_404, known_404 = http.identify_404(host,port)
  if ( status_404 and result_404 == 200 ) then
    stdnse.debug1("Exiting due to ambiguous response from web server on %s:%s. All URIs return status 200.", host.ip, port.number)
    return nil
  end

  -- Queue up the checks
  local all = {}

  -- Remove trailing slash, if it exists
  if(#basepath > 1 and string.sub(basepath, #basepath, #basepath) == '/') then
    basepath = string.sub(basepath, 1, #basepath - 1)
  end

  -- Add a leading slash, if it doesn't exist
  if(#basepath <= 1) then
    basepath = ''
  else
    if(string.sub(basepath, 1, 1) ~= '/') then
      basepath = '/' .. basepath
    end
  end

  local results_nopipeline = {}
  -- Loop through the fingerprints
  stdnse.debug1("Searching for entries under path '%s' (change with 'http-enum.basepath' argument)", basepath)
  for i = 1, #fingerprints, 1 do
    -- Add each path. The order very much matters here.
    for j = 1, #fingerprints[i].probes, 1 do
      local probe = fingerprints[i].probes[j]
      if probe.nopipeline then
        local res = http.generic_request(host, port, probe.method or 'GET', basepath .. probe.path, probe.options or nil)
        if res.status then
          table.insert(results_nopipeline, res)
        else
          table.insert(results_nopipeline, false)
        end
      else
        all = http.pipeline_add(basepath .. probe.path, probe.options or nil, all, probe.method or 'GET')
      end
    end
  end

  -- Perform all the requests.
  local results = http.pipeline_go(host, port, all)

  -- Check for http.pipeline error
  if(results == nil) then
    stdnse.debug1("http.pipeline_go encountered an error")
    return stdnse.format_output(false, "http.pipeline_go encountered an error")
  end

  -- Loop through the fingerprints. Note that for each fingerprint, we may have multiple results
  local j = 1
  local j_nopipeline = 1
  for i, fingerprint in ipairs(fingerprints) do

    -- Loop through the paths for each fingerprint in the same order we did the requests. Each of these will
    -- have one result, so increment the result value at each iteration
    for _, probe in ipairs(fingerprint.probes) do
      local result
      if probe.nopipeline then
        result = results_nopipeline[j_nopipeline]
        j_nopipeline = j_nopipeline + 1
      else
        result = results[j]
        j = j + 1
      end
      if(result) then
        local path = basepath .. probe['path']
        local good = true
        local output = nil
        -- Unless this check said to ignore 404 messages, check if we got a valid page back using a known 404 message.
        if(fingerprint.ignore_404 ~= true and not(http.page_exists(result, result_404, known_404, path, displayall))) then
          good = false
        else
          -- Loop through our matches table and see if anything matches our result
          for _, match in ipairs(fingerprint.matches) do
            if(match.match) then
              local result, matches = http.response_contains(result, match.match)
              if(result) then
                output = match.output
                good = true
                for k, value in ipairs(matches) do
                  output = string.gsub(output, '\\' .. k, matches[k])
                end
              end
            else
              output = match.output
            end

            -- If nothing matched, turn off the match
            if(not(output)) then
              good = false
            end

            -- If we match the 'dontmatch' line, we're not getting a match
            if(match.dontmatch and match.dontmatch ~= '' and http.response_contains(result, match.dontmatch)) then
              output = nil
              good = false
            end

            -- Break the loop if we found it
            if(output) then
              break
            end
          end
        end

        if(good) then
          -- Save the path in the registry
          http.save_path(stdnse.get_hostname(host), port.number, path, result.status)

          -- Add the path to the output
          output = string.format("%s: %s", path, output)

          -- Build the status code, if it isn't a 200
          if(result.status ~= 200) then
            output = output .. " (" .. http.get_status_string(result) .. ")"
          end

          stdnse.debug1("Found a valid page! %s", output)

          table.insert(response, output)
        end
      end
    end
  end

  return stdnse.format_output(true, response)
end
```
</p>
</details>
---
  
## 3. ssh-brute.nse

##### Simply putting this script Performs brute-force password guessing against ssh servers

```
Categories: brute, intrusive
Download: https://svn.nmap.org/nmap/scripts/ssh-brute.nse
```
<details><summary>ssh-brute.nse</summary>
<p>
  
```lua
local shortport = require "shortport"
local stdnse = require "stdnse"
local brute = require "brute"
local creds = require "creds"

local libssh2_util = require "libssh2-utility"

description = [[
Performs brute-force password guessing against ssh servers.
]]

---
-- @usage
--   nmap -p 22 --script ssh-brute --script-args userdb=users.lst,passdb=pass.lst \
--       --script-args ssh-brute.timeout=4s <target>
--
-- @output
-- 22/ssh open  ssh
-- | ssh-brute:
-- |  Accounts
-- |    username:password
-- |  Statistics
-- |_   Performed 32 guesses in 25 seconds.
--
-- @args ssh-brute.timeout    Connection timeout (default: "5s")

author = "Devin Bjelland"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {
  'brute',
  'intrusive',
}

portrule = shortport.ssh

local arg_timeout = stdnse.get_script_args(SCRIPT_NAME .. ".timeout") or "5s"

Driver = {
  new = function (self, host, port, options)
    stdnse.debug(2, "creating brute driver")
    local o = {
      helper = libssh2_util.SSHConnection:new(),
    }
    setmetatable(o, self)
    self.__index = self
    o.host = host
    o.port = port
    o.options = options
    return o
  end,

  connect = function (self)
    local status, err = self.helper:connect_pcall(self.host, self.port)
    if not status then
      stdnse.debug(2, "libssh2 error: %s", self.helper.session)
      local err = brute.Error:new(self.helper.session)
      err:setReduce(true)
      return false, err
    elseif not self.helper.session then
      stdnse.debug(2, "failure to connect: %s", err)
      local err = brute.Error:new(err)
      err:setAbort(true)
      return false, err
    else
      self.helper:set_timeout(self.options.ssh_timeout)
      return true
    end
  end,

  login = function (self, username, password)
    stdnse.verbose(1, "Trying username/password pair: %s:%s", username, password)
    local status, resp = self.helper:password_auth(username, password)
    if status then
      return true, creds.Account:new(username, password, creds.State.VALID)
    end
    return false, brute.Error:new "Incorrect password"
  end,

  disconnect = function (self)
    return self.helper:disconnect()
  end,
}

local function password_auth_allowed (host, port)
  local helper = libssh2_util.SSHConnection:new()
  if not helper:connect(host, port) then
    return "Failed to connect to ssh server"
  end
  local methods = helper:list "root"
  if methods then
    for _, value in pairs(methods) do
      if value == "password" then
        return true
      end
    end
  end
  return false
end

function action (host, port)
  local timems = stdnse.parse_timespec(arg_timeout) --todo: use this!
  local ssh_timeout = 1000 * timems
  if password_auth_allowed(host, port) then
    local options = {
      ssh_timeout = ssh_timeout,
    }
    local engine = brute.Engine:new(Driver, host, port, options)
    engine.options.script_name = SCRIPT_NAME
    local _, result = engine:start()
    return result
  else
    return "Password authentication not allowed"
  end
end

```
</p>
</details>
---
  
## 4. vulscan.nse

##### Vulscan is a module which enhances nmap to a vulnerability scanner. The
nmap option -sV enables version detection per service which is used to
determine potential flaws according to the identified product. The data
is looked up in an offline version of VulDB.

```
Categories: will be added
Download: https://github.com/scipag/vulscan/releases
Download: https://www.computec.ch/projekte/vulscan/
```
<details><summary>vulscan-config</summary>
<p>


#### Installation
##### Please install the files into the following folder of your Nmap
installation:
```
Nmap\scripts\vulscan\*
```
#### Usage
##### You have to run the following minimal command to initiate a simple vulnerability scan:

```
nmap -sV --script=vulscan/vulscan.nse www.example.com
```

#### Vulnerability Database
##### There are the following pre-installed databases available at the moment:

##### scipvuldb.csv - https://vuldb.com
##### cve.csv - https://cve.mitre.org
##### securityfocus.csv - https://www.securityfocus.com/bid/
##### xforce.csv - https://exchange.xforce.ibmcloud.com/
##### expliotdb.csv - https://www.exploit-db.com
##### openvas.csv - http://www.openvas.org
##### securitytracker.csv - https://www.securitytracker.com (end-of-life)
##### osvdb.csv - http://www.osvdb.org (end-of-life)

#### You may execute vulscan with the following argument to use a single database:
```
--script-args vulscandb=your_own_database
```

#### It is also possible to create and reference your own databases. This requires to create a database file, which has the following structure:
```
<id>;<title>
```

##### Just execute vulscan like you would by refering to one of the pre-delivered databases. Feel free to share your own database and vulnerability connection with me, to add it to the official repository.


#### Update Database
##### The vulnerability databases are updated and assembled on a regularly basis. To support the latest disclosed vulnerabilities, keep your local vulnerability databases up-to-date.

##### To automatically update the databases, simply set execution permissions to the update.sh file and run it:
```
chmod 744 update.sh
./update.sh
```

##### If you want to manually update your databases, go to the following web site and download these files:
- https://www.computec.ch/projekte/vulscan/download/cve.csv
- https://www.computec.ch/projekte/vulscan/download/exploitdb.csv
- https://www.computec.ch/projekte/vulscan/download/openvas.csv
- https://www.computec.ch/projekte/vulscan/download/osvdb.csv
- https://www.computec.ch/projekte/vulscan/download/scipvuldb.csv
- https://www.computec.ch/projekte/vulscan/download/securityfocus.csv
- https://www.computec.ch/projekte/vulscan/download/securitytracker.csv
- https://www.computec.ch/projekte/vulscan/download/xforce.csv

##### Copy the files into your vulscan folder:
```
/vulscan/
```

#### Version Detection
##### If the version detection was able to identify the software version and the vulnerability database is providing such details, also this data is matched. 
##### Disabling this feature might introduce false-positive but might also eliminate false-negatives and increase performance slighty. If you want to disable additional version matching, use the following argument:
```
--script-args vulscanversiondetection=0
```
##### Version detection of vulscan is only as good as Nmap version detection and the vulnerability database entries are. Some databases do not provide conclusive version information, which may lead to a lot of false-positives (as can be seen for Apache servers).

#### Match Priority
##### The script is trying to identify the best matches only. If no positive match could been found, the best possible match (with might be a false-positive) is put on display.

##### If you want to show all matches, which might introduce a lot of false-positives but might be useful for further investigation, use the following argument:
```
--script-args vulscanshowall=1
```

#### Interactive Mode
##### The interactive mode helps you to override version detection results for every port. Use the following argument to enable the interactive mode:
```
--script-args vulscaninteractive=1
```

#### Reporting
##### All matching results are printed one by line. The default layout for this is:
```
[{id}] {title}\n
```
##### It is possible to use another pre-defined report structure with the following argument:
```
--script-args vulscanoutput=details
--script-args vulscanoutput=listid
--script-args vulscanoutput=listlink
--script-args vulscanoutput=listtitle
```
##### You may enforce your own report structure by using the following argument (some examples):
```
--script-args vulscanoutput='{link}\n{title}\n\n'
--script-args vulscanoutput='ID: {id} - Title: {title} ({matches})\n'
--script-args vulscanoutput='{id} | {product} | {version}\n'
```
##### Supported are the following elements for a dynamic report template:
```
{id} - ID of the vulnerability
{title} - Title of the vulnerability
{matches} - Count of matches
{product} - Matched product string(s)
{version} - Matched version string(s)
{link} - Link to the vulnerability database entry
\n - Newline
\t - Tab
```
##### Every default database comes with an url and a link, which is used during the scanning and might be accessed as {link} within the customized report template. To use custom database links, use the following argument:
```
--script-args "vulscandblink=http://example.org/{id}"
```
#### Disclaimer
##### Keep in mind that this kind of derivative vulnerability scanning heavily relies on the confidence of the version detection of nmap, the amount of documented vulnerabilities and the accuracy of pattern matching. The existence of potential flaws is not verified with additional scanning nor exploiting techniques.
</p>
</details>


<details><summary>vulscan.nse</summary>
<p>

```lua
author = "Marc Ruef, marc.ruef-at-computec.ch, https://www.computec.ch/mruef/"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "vuln"}

local stdnse = require("stdnse")
local have_stringaux, stringaux = pcall(require, "stringaux")
local strsplit = (have_stringaux and stringaux or stdnse).strsplit

portrule = function(host, port)
	if port.version.product ~= nil and port.version.product ~= "" then
		return true
	else
		stdnse.print_debug(1, "vulscan: No version detection data available. Analysis not possible.")
	end
end

action = function(host, port)
	local prod = port.version.product	-- product name
	local ver = port.version.version	-- product version
	local struct = "[{id}] {title}\n"	-- default report structure
	local db = {}				-- vulnerability database
	local db_link = ""			-- custom link for vulnerability databases
	local vul = {}				-- details for the vulnerability
	local v_count = 0			-- counter for the vulnerabilities
	local s = ""				-- the output string

	stdnse.print_debug(1, "vulscan: Found service " .. prod)

	-- Go into interactive mode
	if nmap.registry.args.vulscaninteractive == "1" then
		stdnse.print_debug(1, "vulscan: Enabling interactive mode ...")
		print("The scan has determined the following product:")
		print(prod)
		print("Press Enter to accept. Define new string to override.")
		local prod_override = io.stdin:read'*l'

		if string.len(prod_override) ~= 0 then
			prod = prod_override
			stdnse.print_debug(1, "vulscan: Product overwritten as " .. prod)
		end
	end

	-- Read custom report structure
	if nmap.registry.args.vulscanoutput ~= nil then
		if nmap.registry.args.vulscanoutput == "details" then
			struct = "[{id}] {title}\nMatches: {matches}, Prod: {product}, Ver: {version}\n{link}\n\n"
		elseif nmap.registry.args.vulscanoutput == "listid" then
			struct = "{id}\n"
		elseif nmap.registry.args.vulscanoutput == "listlink" then
			struct = "{link}\n"
		elseif nmap.registry.args.vulscanoutput == "listtitle" then
			struct = "{title}\n"
		else
			struct = nmap.registry.args.vulscanoutput
		end

		stdnse.print_debug(1, "vulscan: Custom output structure defined as " .. struct)
	end

	-- Read custom database link
	if nmap.registry.args.vulscandblink ~= nil then
		db_link = nmap.registry.args.vulscandblink
		stdnse.print_debug(1, "vulscan: Custom database link defined as " .. db_link)
	end

	if nmap.registry.args.vulscandb then
		stdnse.print_debug(1, "vulscan: Using single mode db " .. nmap.registry.args.vulscandb .. " ...")
		vul = find_vulnerabilities(prod, ver, nmap.registry.args.vulscandb)
		if #vul > 0 then
			s = s .. nmap.registry.args.vulscandb
			if db_link ~= "" then s = s .. " - " .. db_link end
			s = s .. ":\n" .. prepare_result(vul, struct, db_link) .. "\n\n"
		end
	else
		-- Add your own database, if you want to include it in the multi db mode
		db[1] = {name="VulDB",			file="scipvuldb.csv",		url="https://vuldb.com",			link="https://vuldb.com/id.{id}"}
		db[2] = {name="MITRE CVE",		file="cve.csv",			url="https://cve.mitre.org",			link="https://cve.mitre.org/cgi-bin/cvename.cgi?name={id}"}
		db[3] = {name="SecurityFocus",		file="securityfocus.csv",	url="https://www.securityfocus.com/bid/",	link="https://www.securityfocus.com/bid/{id}"}
		db[4] = {name="IBM X-Force",		file="xforce.csv",		url="https://exchange.xforce.ibmcloud.com",	link="https://exchange.xforce.ibmcloud.com/vulnerabilities/{id}"}
		db[5] = {name="Exploit-DB",		file="exploitdb.csv",		url="https://www.exploit-db.com",		link="https://www.exploit-db.com/exploits/{id}"}
		db[6] = {name="OpenVAS (Nessus)",	file="openvas.csv",		url="http://www.openvas.org",			link="https://www.tenable.com/plugins/nessus/{id}"}
		db[7] = {name="SecurityTracker",	file="securitytracker.csv",	url="https://www.securitytracker.com",		link="https://www.securitytracker.com/id/{id}"}
		db[8] = {name="OSVDB",			file="osvdb.csv",		url="http://www.osvdb.org",			link="http://www.osvdb.org/{id}"}

		stdnse.print_debug(1, "vulscan: Using multi db mode (" .. #db .. " databases) ...")
		for i,v in ipairs(db) do
			vul = find_vulnerabilities(prod, ver, v.file)

			s = s .. v.name .. " - " .. v.url .. ":\n"
			if #vul > 0 then
					v_count = v_count + #vul
					s = s .. prepare_result(vul, struct, v.link) .. "\n"
			else
					s = s .. "No findings\n\n"
			end

			stdnse.print_debug(1, "vulscan: " .. #vul .. " matches in " .. v.file)
		end

		stdnse.print_debug(1, "vulscan: " .. v_count .. " matches in total")
	end

	if s then
		return s
	end
end

-- Find the product matches in the vulnerability databases
function find_vulnerabilities(prod, ver, db)
	local v = {}			-- matching vulnerabilities
	local v_id			-- id of vulnerability
	local v_title			-- title of vulnerability
	local v_title_lower		-- title of vulnerability in lowercase for speedup
	local v_found			-- if a match could be found

	-- Load database
	local v_entries = read_from_file("scripts/vulscan/" .. db)

	-- Clean useless dataparts (speeds up search and improves accuracy)
	prod = string.gsub(prod, " httpd", "")
	prod = string.gsub(prod, " smtpd", "")
	prod = string.gsub(prod, " ftpd", "")

	local prod_words = strsplit(" ", prod)

	stdnse.print_debug(1, "vulscan: Starting search of " .. prod ..
		" in " .. db ..
		" (" .. #v_entries .. " entries) ...")

	-- Iterate through the vulnerabilities in the database
	for i=1, #v_entries, 1 do
		v_id		= extract_from_table(v_entries[i], 1, ";")
		v_title		= extract_from_table(v_entries[i], 2, ";")

		if type(v_title) == "string" then
			v_title_lower = string.lower(v_title)

			-- Find the matches for the database entry
			for j=1, #prod_words, 1 do
				v_found = string.find(v_title_lower, escape(string.lower(prod_words[j])), 1)
				if type(v_found) == "number" then
					if #v == 0 then
						-- Initiate table
						v[1] = {
							id		= v_id,
							title	= v_title,
							product	= prod_words[j],
							version	= "",
							matches	= 1
						}
					elseif v[#v].id ~= v_id then
						-- Create new entry
						v[#v+1] = {
							id		= v_id,
							title	= v_title,
							product	= prod_words[j],
							version	= "",
							matches	= 1
						}
					else
						-- Add to current entry
						v[#v].product = v[#v].product .. " " .. prod_words[j]
						v[#v].matches = v[#v].matches+1
					end

					stdnse.print_debug(2, "vulscan: Match v_id " .. v_id ..
						" -> v[" .. #v .. "] " ..
						"(" .. v[#v].matches .. " match) " ..
						"(Prod: " .. prod_words[j] .. ")")
				end
			end

			-- Additional version matching
			if nmap.registry.args.vulscanversiondetection ~= "0" and ver ~= nil and ver ~= "" then
				if v[#v] ~= nil and v[#v].id == v_id then
					for k=0, string.len(ver)-1, 1 do
						v_version = string.sub(ver, 1, string.len(ver)-k)
						v_found = string.find(string.lower(v_title), string.lower(" " .. v_version), 1)

						if type(v_found) == "number" then
							v[#v].version = v[#v].version .. v_version .. " "
							v[#v].matches = v[#v].matches+1

							stdnse.print_debug(2, "vulscan: Match v_id " .. v_id ..
								" -> v[" .. #v .. "] " ..
								"(" .. v[#v].matches .. " match) " ..
								"(Version: " .. v_version .. ")")
						end
					end
				end
			end
		end
	end

	return v
end

-- Prepare the resulting matches
function prepare_result(v, struct, link)
	local grace = 0				-- grace trigger
	local match_max = 0			-- counter for maximum matches
	local match_max_title = ""	-- title of the maximum match
	local s = ""				-- the output string

	-- Search the entries with the best matches
	if #v > 0 then
		-- Find maximum matches
		for i=1, #v, 1 do
			if v[i].matches > match_max then
				match_max = v[i].matches
				match_max_title = v[i].title
			end
		end

		stdnse.print_debug(2, "vulscan: Maximum matches of a finding are " ..
			match_max .. " (" .. match_max_title .. ")")

		if match_max > 0 then
			for matchpoints=match_max, 1, -1 do
				for i=1, #v, 1 do
					if v[i].matches == matchpoints then
						stdnse.print_debug(2, "vulscan: Setting up result id " .. i)
						s = s .. report_parsing(v[i], struct, link)
					end
				end

				if nmap.registry.args.vulscanshowall ~= "1" and s ~= "" then
					-- If the next iteration shall be approached (increases matches)
					if grace == 0 then
						stdnse.print_debug(2, "vulscan: Best matches found in 1st pass. Going to use 2nd pass ...")
						grace = grace+1
					elseif nmap.registry.args.vulscanshowall ~= "1" then
						break
					end
				end
			end
		end
	end

	return s
end

-- Parse the report output structure
function report_parsing(v, struct, link)
	local s = struct

	--database data (needs to be first)
	s = string.gsub(s, "{link}", escape(link))

	--layout elements (needs to be second)
	s = string.gsub(s, "\\n", "\n")
	s = string.gsub(s, "\\t", "\t")

	--vulnerability data (needs to be third)
	s = string.gsub(s, "{id}", escape(v.id))
	s = string.gsub(s, "{title}", escape(v.title))
	s = string.gsub(s, "{matches}", escape(v.matches))
	s = string.gsub(s, "{product}", escape(v.product))	
	s = string.gsub(s, "{version}", escape(v.version))

	return s
end

-- Get the row of a CSV file
function extract_from_table(line, col, del)
	local val = strsplit(del, line)

	if type(val[col]) == "string" then
		return val[col]
	end
end

-- Read a file
function read_from_file(file)
	local filepath = nmap.fetchfile(file)

	if filepath then
		local f, err, _ = io.open(filepath, "r")
		if not f then
			stdnse.print_debug(1, "vulscan: Failed to open file" .. file)
		end

		local line, ret = nil, {}
		while true do
			line = f:read()
			if not line then break end
			ret[#ret+1] = line
		end

		f:close()

		return ret
	else
		stdnse.print_debug(1, "vulscan: File " .. file .. " not found")
		return ""
	end
end

-- We don't like unescaped things
function escape(s)
	s = string.gsub(s, "%%", "%%%%")
	return s
end
```
</p>
</details>
----------------------------------------------------
  
## 5. smb-brute.nse

##### General Description
```
Categories: intrusive, brute
Download: https://svn.nmap.org/nmap/scripts/smb-brute.nse
```

#### Example Usage
```
nmap --script smb-brute.nse -p445 <host>
sudo nmap -sU -sS --script smb-brute.nse -p U:137,T:139 <host>
```

##### Attempts to guess username/password combinations over SMB, storing discovered combinations for use in other scripts. Every attempt will be made to get a valid list of users and to verify each username before actually using them. When a username is discovered, besides being printed, it is also saved in the Nmap registry so other Nmap scripts can use it. That means that if you're going to run smb-brute.nse, you should run other smb scripts you want. This checks passwords in a case-insensitive way, determining case after a password is found, for Windows versions before Vista.
##### This script is specifically targeted towards security auditors or penetration testers. One example of its use, suggested by Brandon Enright, was hooking up smb-brute.nse to the database of usernames and passwords used by the Conficker worm (the password list can be found at http://www.skullsecurity.org/wiki/index.php/Passwords, among other places. Then, the network is scanned and all systems that would be infected by Conficker are discovered.
##### From the penetration tester perspective its use is pretty obvious. By discovering weak passwords on SMB, a protocol that's well suited for bruteforcing, access to a system can be gained. Further, passwords discovered against Windows with SMB might also be used on Linux or MySQL or custom Web applications. Discovering a password greatly beneficial for a pen-tester.

<details><summary>smb-brute.nse</summary>
<p>
  
```lua
local msrpc = require "msrpc"
local nmap = require "nmap"
local smb = require "smb"
local stdnse = require "stdnse"
local string = require "string"
local stringaux = require "stringaux"
local table = require "table"
local unpwdb = require "unpwdb"
local rand = require "rand"

description = [[
Attempts to guess username/password combinations over SMB, storing discovered combinations
for use in other scripts. Every attempt will be made to get a valid list of users and to
verify each username before actually using them. When a username is discovered, besides
being printed, it is also saved in the Nmap registry so other Nmap scripts can use it. That
means that if you're going to run <code>smb-brute.nse</code>, you should run other <code>smb</code> scripts you want.
This checks passwords in a case-insensitive way, determining case after a password is found,
for Windows versions before Vista.

This script is specifically targeted towards security auditors or penetration testers.
One example of its use, suggested by Brandon Enright, was hooking up <code>smb-brute.nse</code> to the
database of usernames and passwords used by the Conficker worm (the password list can be
found at http://www.skullsecurity.org/wiki/index.php/Passwords, among other places.
Then, the network is scanned and all systems that would be infected by Conficker are
discovered.

From the penetration tester perspective its use is pretty obvious. By discovering weak passwords
on SMB, a protocol that's well suited for bruteforcing, access to a system can be gained.
Further, passwords discovered against Windows with SMB might also be used on Linux or MySQL
or custom Web applications. Discovering a password greatly beneficial for a pen-tester.

This script uses a lot of little tricks that I (Ron Bowes) describe in detail in a blog
posting, http://www.skullsecurity.org/blog/?p=164. The tricks will be summarized here, but
that blog is the best place to learn more.

Usernames and passwords are initially taken from the unpwdb library. If possible, the usernames
are verified as existing by taking advantage of Windows' odd behaviour with invalid username
and invalid password responses. As soon as it is able, this script will download a full list
of usernames from the server and replace the unpw usernames with those. This enables the
script to restrict itself to actual accounts only.

When an account is discovered, it's saved in the <code>smb</code> module (which uses the Nmap
registry). If an account is already saved, the account's privileges are checked; accounts
with administrator privileges are kept over accounts without. The specific method for checking
is by calling <code>GetShareInfo("IPC$")</code>, which requires administrative privileges. Once this script
is finished (all other smb scripts depend on it, it'll run first), other scripts will use the saved account
to perform their checks.

The blank password is always tried first, followed by "special passwords" (such as the username
and the username reversed). Once those are exhausted, the unpwdb password list is used.

One major goal of this script is to avoid account lockouts. This is done in a few ways. First,
when a lockout is detected, unless you user specifically overrides it with the <code>smblockout</code>
argument, the scan stops. Second, all usernames are checked with the most common passwords first,
so with not-too-strict lockouts (10 invalid attempts), the 10 most common passwords will still
be tried. Third, one account, called the canary, "goes out ahead"; that is, three invalid
attempts are made (by default) to ensure that it's locked out before others are.

In addition to active accounts, this script will identify valid passwords for accounts that
are disabled, guest-equivalent, and require password changes. Although these accounts can't
be used, it's good to know that the password is valid. In other cases, it's impossible to
tell a valid password (if an account is locked out, for example). These are displayed, too.
Certain accounts, such as guest or some guest-equivalent, will permit any password. This
is also detected. When possible, the SMB protocol is used to its fullest to get maximum
information.

When possible, checks are done using a case-insensitive password, then proper case is
determined with a fairly efficient bruteforce. For example, if the actual password is
"PassWord", then "password" will work and "PassWord" will be found afterwards (on the
14th attempt out of a possible 256 attempts, with the current algorithm).
]]
---
--@usage
-- nmap --script smb-brute.nse -p445 <host>
-- sudo nmap -sU -sS --script smb-brute.nse -p U:137,T:139 <host>
--
--@output
-- Host script results:
-- | smb-brute:
-- |   bad name:test => Valid credentials
-- |   consoletest:test => Valid credentials, password must be changed at next logon
-- |   guest:<anything> => Valid credentials, account disabled
-- |   mixcase:BuTTeRfLY1 => Valid credentials
-- |   test:password1 => Valid credentials, account expired
-- |   this:password => Valid credentials, account cannot log in at current time
-- |   thisisaverylong:password => Valid credentials
-- |   thisisaverylongname:password => Valid credentials
-- |   thisisaverylongnamev:password => Valid credentials
-- |_  web:TeSt => Valid credentials, account disabled
--
-- @args smblockout This argument will force the script to continue if it
--       locks out an account or thinks it will lock out an account.
-- @args brutelimit Limits the number of usernames checked in the script. In some domains,
--       it's possible to end up with 10,000+ usernames on each server. By default, this
--       will be <code>5000</code>, which should be higher than most servers and also prevent infinite
--       loops or other weird things. This will only affect the user list pulled from the
--       server, not the username list.
-- @args canaries Sets the number of tests to do to attempt to lock out the first account.
--       This will lock out the first account without locking out the rest of the accounts.
--       The default is 3, which will only trigger strict lockouts, but will also bump the
--       canary account up far enough to detect a lockout well before other accounts are
--       hit.
----


author = "Ron Bowes"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"intrusive", "brute"}


---The maximum number of usernames to check (can be modified with smblimit argument)
-- The limit exists because domains may have hundreds of thousands of accounts,
-- potentially.
local LIMIT = 5000

hostrule = function(host)
  return smb.get_port(host) ~= nil
end

---The possible result codes. These are simplified from the actual codes that SMB returns.
local results =
{
  SUCCESS             =  1, -- Login was successful
  GUEST_ACCESS        =  2, -- Login was successful, but was granted guest access
  NOT_GRANTED         =  3, -- Password was correct, but user wasn't allowed to log in (often happens with blank passwords)
  DISABLED            =  4, -- Password was correct, but user's account is disabled
  EXPIRED             =  5, -- Password was correct, but user's account is expired
  CHANGE_PASSWORD     =  6, -- Password was correct, but user can't log in without changing it
  ACCOUNT_LOCKED      =  7, -- User's account is locked out (hopefully not by us!)
  ACCOUNT_LOCKED_NOW  =  8, -- User's account just became locked out (oops!)
  FAIL                =  9, -- User's password was incorrect
  INVALID_LOGON_HOURS = 10, -- Password was correct, but user's account has logon time restrictions in place
  INVALID_WORKSTATION = 11  -- Password was correct, but user's account has workstation restrictions in place
}

---Strings for debugging output
local result_short_strings = {}
result_short_strings[results.SUCCESS]             = "SUCCESS"
result_short_strings[results.GUEST_ACCESS]        = "GUEST_ACCESS"
result_short_strings[results.NOT_GRANTED]         = "NOT_GRANTED"
result_short_strings[results.DISABLED]            = "DISABLED"
result_short_strings[results.EXPIRED]             = "EXPIRED"
result_short_strings[results.CHANGE_PASSWORD]     = "CHANGE_PASSWORD"
result_short_strings[results.ACCOUNT_LOCKED]      = "LOCKED"
result_short_strings[results.ACCOUNT_LOCKED_NOW]  = "LOCKED_NOW"
result_short_strings[results.FAIL]                = "FAIL"
result_short_strings[results.INVALID_LOGON_HOURS] = "INVALID_LOGON_HOURS"
result_short_strings[results.INVALID_WORKSTATION] = "INVALID_WORKSTATION"


---The strings that the user will see
local result_strings = {}
result_strings[results.SUCCESS]              = "Valid credentials"
result_strings[results.GUEST_ACCESS]         = "Valid credentials, account granted guest access only"
result_strings[results.NOT_GRANTED]          = "Valid credentials, but account wasn't allowed to log in (often happens with blank passwords)"
result_strings[results.DISABLED]             = "Valid credentials, account disabled"
result_strings[results.EXPIRED]              = "Valid credentials, account expired"
result_strings[results.CHANGE_PASSWORD]      = "Valid credentials, password must be changed at next logon"
result_strings[results.ACCOUNT_LOCKED]       = "Valid credentials, account locked (hopefully not by us!)"
result_strings[results.ACCOUNT_LOCKED_NOW]   = "Valid credentials, account just became locked (oops!)"
result_strings[results.FAIL]                 = "Invalid credentials"
result_strings[results.INVALID_LOGON_HOURS]  = "Valid credentials, account cannot log in at current time"
result_strings[results.INVALID_WORKSTATION]  = "Valid credentials, account cannot log in from current host"

---Constants for special passwords. These each contain a null character, which is illegal in
-- actual passwords.
local USERNAME          = "\0username"
local USERNAME_REVERSED = "\0username reversed"
local special_passwords = { USERNAME, USERNAME_REVERSED }

---Generates a random string of the requested length. This can be used to check how hosts react to
-- weird username/password combinations.
--@param length (optional) The length of the string to return. Default: 8.
--@param set    (optional) The set of letters to choose from. Default: upper, lower, numbers, and underscore.
--@return The random string.
local function get_random_string(length)
  return rand.random_string(length, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")
end

---Splits a string in the form "domain\user" into domain and user.
--@param str The string to split
--@return (domain, username) The domain and the username. If no domain was given, nil is returned
--        for domain.
local function split_domain(str)
  local username, domain
  local split = stringaux.strsplit("\\", str)

  if(#split > 1) then
    domain = split[1]
    username = split[2]
  else
    domain   = nil
    username = str
  end

  return domain, username
end

---Formats a username/password pair with an optional result. Just a way to keep things consistent
-- throughout the program. Currently, the format is "username:password => result".
--@param username The username.
--@param password [optional] The password. Default: "<unknown>".
--@param result   [optional] The result, as a constant. Default: not used.
--@return A string representing the input values.
local function format_result(username, password, result)

  if(username == "") then
    username = "<blank>"
  end

  if(password == nil) then
    password = "<unknown>"
  elseif(password == "") then
    password = "<blank>"
  end

  if(result == nil) then
    return string.format("%s:%s", username, password)
  else
    return string.format("%s:%s => %s", username, password, result_strings[result])
  end
end

---Decides which login type to use (lanman, ntlm, or other). Designed to keep things consistent.
--@param hostinfo The hostinfo table.
--@return A string representing the login type to use (that can be passed to SMB functions).
local function get_type(hostinfo)
  -- Check if the user requested a specific type
  if(nmap.registry.args.smbtype ~= nil) then
    return nmap.registry.args.smbtype
  end

  -- Otherwise, base the type on the operating system (TODO: other versions of Windows (7, 2008))
  -- 2k8 example: "Windows Server (R) 2008 Datacenter without Hyper-V 6001 Service Pack 1"
  if(string.find(string.lower(hostinfo['os']), "vista") ~= nil) then
    return "ntlm"
  elseif(string.find(string.lower(hostinfo['os']), "2008") ~= nil) then
    return "ntlm"
  elseif(string.find(string.lower(hostinfo['os']), "Windows 7") ~= nil) then
    return "ntlm"
  end

  return "lm"
end

---Stops the session, if one exists. This can be called as frequently as needed, it'll just return if no
-- session is present, but it should generally be paired with a <code>restart_session</code> call.
--@param hostinfo The hostinfo table.
--@return (status, err) If status is false, err is a string corresponding to the error; otherwise, err is undefined.
local function stop_session(hostinfo)
  local status, err

  if(hostinfo['smbstate'] ~= nil) then
    stdnse.debug2("Stopping the SMB session")
    status, err = smb.stop(hostinfo['smbstate'])
    if(status == false) then
      return false, err
    end

    hostinfo['smbstate'] = nil
  end


  return true
end

---Starts or restarts a SMB session with the host. Although this will automatically stop a session if
-- one exists, it's a little cleaner to pair this with a <code>stop_session</code> call.
--@param hostinfo The hostinfo table.
--@return (status, err) If status is false, err is a string corresponding to the error; otherwise, err is undefined.
local function restart_session(hostinfo)
  local status, err, smbstate

  -- Stop the old session, if it exists
  stop_session(hostinfo)

  stdnse.debug2("Starting the SMB session")
  status, smbstate = smb.start_ex(hostinfo['host'], true, nil, nil, nil, true)
  if(status == false) then
    return false, smbstate
  end

  hostinfo['smbstate'] = smbstate

  return true
end

---Attempts to log into an account, returning one of the <code>results</code> constants. Will always return to the
-- state where another login can be attempted. Will also differentiate between a hash and a password, and choose the
-- proper login method (unless overridden). Will interpret the result as much as possible.
--
-- The session has to be active (ie, <code>restart_session</code> has to be called) before calling this function.
--
--@param hostinfo The hostinfo table.
--@param username The username to try.
--@param password The password to try.
--@param logintype [optional] The logintype to use. Default: <code>get_type</code> is called. If <code>password</code>
--       is a hash, this is ignored.
--@return Result, an integer value from the <code>results</code> constants.
local function check_login(hostinfo, username, password, logintype)
  local result
  local domain = ""
  local smbstate = hostinfo['smbstate']
  if(logintype == nil) then
    logintype = get_type(hostinfo)
  end

  -- Determine if we have a password hash or a password
  local status, err
  if(#password == 32 or #password == 64 or #password == 65) then
    -- It's a hash (note: we always use NTLM hashes)
    status, err = smb.start_session(smbstate, smb.get_overrides(username, domain, nil, password, "ntlm"), false)
  else
    status, err = smb.start_session(smbstate, smb.get_overrides(username, domain, password, nil, logintype), false)
  end

  if(status == true) then
    if(smbstate['is_guest'] == 1) then
      result = results.GUEST_ACCESS
    else
      result = results.SUCCESS
    end

    smb.logoff(smbstate)
  else
    if(err == "NT_STATUS_LOGON_TYPE_NOT_GRANTED") then
      result = results.NOT_GRANTED
    elseif(err == "NT_STATUS_ACCOUNT_LOCKED_OUT") then
      result = results.ACCOUNT_LOCKED
    elseif(err == "NT_STATUS_ACCOUNT_DISABLED") then
      result = results.DISABLED
    elseif(err == "NT_STATUS_PASSWORD_MUST_CHANGE") then
      result = results.CHANGE_PASSWORD
    elseif(err == "NT_STATUS_INVALID_LOGON_HOURS") then
      result = results.INVALID_LOGON_HOURS
    elseif(err == "NT_STATUS_INVALID_WORKSTATION") then
      result = results.INVALID_WORKSTATION
    elseif(err == "NT_STATUS_ACCOUNT_EXPIRED") then
      result = results.EXPIRED
    else
      result = results.FAIL
    end
  end

  --io.write(string.format("Result: %s\n\n", result_strings[result]))

  return result
end

---Determines whether or not a login was successful, based on what's known about the server's settings. This
-- is fairly straight forward, but has a couple little tricks.
--
--@param hostinfo The hostinfo table.
--@param result   The result code.
--@return <code>true</code> if the password used for logging in was correct, <code>false</code> otherwise. Keep
--        in mind that this doesn't imply the login was successful (only results.SUCCESS indicates that), rather
--        that the password was valid.

function is_positive_result(hostinfo, result)
  -- If result is a FAIL, it's always bad
  if(result == results.FAIL) then
    return false
  end

  -- If result matches what we discovered for invalid passwords, it's always bad
  if(result == hostinfo['invalid_password']) then
    return false
  end

  -- If result was ACCOUNT_LOCKED, it's always bad (locked accounts should already be taken care of, but this
  -- makes the function a bit more generic)
  if(result == results.ACCOUNT_LOCKED) then
    return false
  end

  -- Otherwise, it's good
  return true
end

---Determines whether or not a login was "bad". A bad login is one where an account becomes locked out.
--
--@param hostinfo The hostinfo table.
--@param result   The result code.
--@return <code>true</code> if the password used for logging in was correct, <code>false</code> otherwise. Keep
--        in mind that this doesn't imply the login was successful (only results.SUCCESS indicates that), rather
--        that the password was valid.

function is_bad_result(hostinfo, result)
  -- If result is LOCKED, it's always bad.
  if(result == results.ACCOUNT_LOCKED or result == results.ACCOUNT_LOCKED_NOW) then
    return true
  end

  -- Otherwise, it's good
  return false
end

---Count the number of one bits in a binary representation of the given number. This is used for case-sensitive
-- checks.
--
--@param num The number to count the ones for.
--@return The number of ones in the number
local function count_ones(num)
  local count = 0

  while num ~= 0 do
    if((num & 1) == 1) then
      count = count + 1
    end
    num = num >> 1
  end

  return count
end

---Converts a string's case based on a binary number. For every '1' bit, the character is uppercased, and for every '0'
-- bit it's lowercased. For example, "test" and 8 (1000) becomes "Test", while "test" and 11 (1011) becomes "TeST".
--
--@param str The string to convert.
--@param num The binary number representing the case. This value isn't checked, so if it's too large it's truncated, and if it's
--           too small it's effectively zero-padded.
--@return The converted string.
local function convert_case(str, num)
  local pos = #str

  -- Don't bother with blank strings (we probably won't get here anyway, but it doesn't hurt)
  if(str == "") then
    return ""
  end

  while(num ~= 0) do
    -- Check if the bit we're at is '1'
    if((num & 1) == 1) then
      -- Check if we're at the beginning or end (or both) of the string -- those are special cases
      if(pos == #str and pos == 1) then
        str = string.upper(string.sub(str, pos, pos))
      elseif(pos == #str) then
        str = string.sub(str, 1, pos - 1) .. string.upper(string.sub(str, pos, pos))
      elseif(pos == 1) then
        str = string.upper(string.sub(str, pos, pos)) .. string.sub(str, pos + 1, #str)
      else
        str = string.sub(str, 1, pos - 1) .. string.upper(string.sub(str, pos, pos)) .. string.sub(str, pos + 1, #str)
      end
    end

    num = num >> 1

    pos = pos - 1
  end

  return str
end

---Attempts to determine the case of a password. This is done by trying every possible combination of upper and lowercase
-- characters in the password, in the most efficient possible ordering, until the correct case is found.
--
-- A session has to be active when this function is called.
--
--@param hostinfo The hostinfo table.
--@param username The username.
--@param password The password (it's assumed that it's all lowercase already, but it doesn't matter)
--@return The password with the proper case, or the original password if it couldn't be determined (either the proper
--        case wasn't found or the login type is incorrect).
local function find_password_case(hostinfo, username, password)
  -- Only do this if we're using lanman, otherwise we already have the proper password
  if(get_type(hostinfo) ~= "lm") then
    return password
  end

  -- Figure out how many possibilities exist
  local max = (1 << #password) - 1

  -- Create an array of them, starting with all the values whose binary representation has no ones, then one one, then two ones, etc.
  local ordered = {}

  -- Cheat a bit, by adding all lower then all upper right at the start
  ordered = {0, max}

  -- Loop backwards from the length of the password to 0. At each spot, put all numbers that have that many '1' bits
  for i = 1, #password - 1, 1 do
    for j = max, 0, -1 do
      if(count_ones(j) == i) then
        table.insert(ordered, j)
      end
    end
  end

  -- Create the list of converted passwords
  for i = 1, #ordered, 1 do
    local thispassword = convert_case(password, ordered[i])

    -- We specify "ntlm" for the login type because it's case sensitive
    local result = check_login(hostinfo, username, thispassword, 'ntlm')
    if(is_positive_result(hostinfo, result)) then
      return thispassword
    end
  end

  -- Print an error message
  stdnse.debug1("ERROR: smb-brute: Was unable to determine case of %s's password", username)

  -- If all else fails, just return the actual password (we probably shouldn't get here)
  return password
end

---Unless the user is ok with lockouts, check the lockout policy of the host. Take the most restrictive
-- portion among the domains. Returns true if lockouts could happen, false otherwise.
local function bad_lockout_policy(host)
  -- If the user is ok with locking out accounts, just return
  if(stdnse.get_script_args( "smblockout" )) then
    stdnse.debug1("Not checking server's lockout policy")
    return true, false
  end

  local status, result = msrpc.get_domains(host)
  if(not(status)) then
    stdnse.debug1("Couldn't detect lockout policy: %s", result)
    return false, "Couldn't retrieve lockout policy: " .. result
  end

  for domain, data in pairs(result) do
    if(data and data.lockout_threshold) then
      stdnse.debug1("Server's lockout policy: lock out after %d attempts", data.lockout_threshold)
      return true, true
    end
  end

  stdnse.debug1("Server has no lockout policy")
  return true, false
end

---Initializes and returns the hostinfo table. This includes queuing up the username and password lists, determining
-- the server's operating system,  and checking the server's response for invalid usernames/invalid passwords.
--
--@param host The host object.
local function initialize(host)
  local os, result
  local status, bad_lockout_policy_result
  local hostinfo = {}

  hostinfo['host'] = host
  hostinfo['invalid_usernames'] = {}
  hostinfo['locked_usernames'] = {}
  hostinfo['accounts'] = {}
  hostinfo['special_password'] = 1

  -- Get the OS (identifying windows versions tells us which hash to use)
  result, os = smb.get_os(host)
  if(result == false or os['os'] == nil) then
    hostinfo['os'] = "<Unknown>"
  else
    hostinfo['os'] = os['os']
  end
  stdnse.debug1("Remote operating system: %s", hostinfo['os'])

  -- Check lockout policy
  status, bad_lockout_policy_result = bad_lockout_policy(host)
  if(not(status)) then
    stdnse.debug1("WARNING: couldn't determine lockout policy: %s", bad_lockout_policy_result)
  else
    if(bad_lockout_policy_result) then
      return false, "Account lockouts are enabled on the host. To continue (and risk lockouts), add --script-args=smblockout=1 -- for more information, run smb-enum-domains."
    end
  end

  -- Attempt to enumerate users
  stdnse.debug1("Trying to get user list from server")
  local _
  hostinfo['have_user_list'], _, hostinfo['user_list'] = msrpc.get_user_list(host)
  hostinfo['user_list_index'] = 1
  if(hostinfo['have_user_list'] and #hostinfo['user_list'] == 0) then
    hostinfo['have_user_list'] = false
  end

  -- If the enumeration failed, try using the built-in list
  if(not(hostinfo['have_user_list'])) then
    stdnse.debug1("Couldn't enumerate users (normal for Windows XP and higher), using unpwdb initially")
    status, hostinfo['user_list_default'] = unpwdb.usernames()
    if(status == false) then
      return false, "Couldn't open username file"
    end
  end

  -- Open the password file
  stdnse.debug1("Opening password list")
  status, hostinfo['password_list'] = unpwdb.passwords()
  if(status == false) then
    return false, "Couldn't open password file"
  end

  -- Start the SMB session
  stdnse.debug1("Starting the initial SMB session")
  local err
  status, err = restart_session(hostinfo)
  if(status == false) then
    stop_session(hostinfo)
    return false, err
  end

  -- Some hosts will accept any username -- check for this by trying to log in with a totally random name. If the
  -- server accepts it, it'll be impossible to bruteforce; if it gives us a weird result code, we have to remember
  -- it.
  hostinfo['invalid_username'] = check_login(hostinfo, get_random_string(8), get_random_string(8), "ntlm")
  hostinfo['invalid_password'] = check_login(hostinfo, "Administrator",      get_random_string(8), "ntlm")

  stdnse.debug1("Server's response to invalid usernames: %s", result_short_strings[hostinfo['invalid_username']])
  stdnse.debug1("Server's response to invalid passwords: %s", result_short_strings[hostinfo['invalid_password']])

  -- If either of these comes back as success, there's no way to tell what's valid/invalid
  if(hostinfo['invalid_username'] == results.SUCCESS) then
    stop_session(hostinfo)
    return false, "Invalid username was accepted; unable to bruteforce"
  end
  if(hostinfo['invalid_password'] == results.SUCCESS) then
    stop_session(hostinfo)
    return false, "Invalid password was accepted; unable to bruteforce"
  end

  -- Print a message to the user if we can identify passwords
  if(hostinfo['invalid_username'] ~= hostinfo['invalid_password']) then
    stdnse.debug1("Invalid username and password response are different, so identifying valid accounts is possible")
  end

  -- Print a warning message if invalid_username and invalid_password go to the same thing that isn't FAIL
  if(hostinfo['invalid_username'] ~= results.FAIL and hostinfo['invalid_username'] == hostinfo['invalid_password']) then
    stdnse.debug1("WARNING: Difficult to recognize invalid usernames/passwords; may not get good results")
  end

  -- Restart the SMB connection so we have a clean slate
  stdnse.debug1("Restarting the session before the bruteforce")
  status, err = restart_session(hostinfo)
  if(status == false) then
    stop_session(hostinfo)
    return false, err
  end

  -- Stop the SMB session (we're going to let the scripts look after their own sessions)
  stop_session(hostinfo)

  -- Return the results
  return true, hostinfo
end

---Retrieves the next password in the password database we're using. Will never return the empty string.
-- May also return one of the <code>special_passwords</code> constants.
--
--@param hostinfo The hostinfo table (the password list is stored there).
--@return The new password, or nil if the end of the list has been reached.
local function get_next_password(hostinfo)
  local new_password

  -- If we're out of special passwords, move onto actual ones
  if(hostinfo['special_password'] > #special_passwords) then
    -- Pick the next non-blank password from the list
    repeat
      new_password = hostinfo['password_list']()
    until new_password ~= ''
  else
    -- Get the next non-blank password
    new_password = special_passwords[hostinfo['special_password']]
    hostinfo['special_password'] = hostinfo['special_password'] + 1
  end

  return new_password
end

---Reset to the first password. This is normally done when the user list changes.
--
--@param hostinfo The hostinfo table.
local function reset_password(hostinfo)
  hostinfo['password_list']("reset")
end

---Retrieves the next username. This can be from the username database, or from an array stored in the
-- hostinfo table. This won't return any names that have been determined to be invalid, locked, or
-- have already had their password found.
--
--@param hostinfo The hostinfo table
--@return The next username, or nil if the end of the list has been reached.
local function get_next_username(hostinfo)
  local username

  repeat
    if(hostinfo['have_user_list']) then
      local index = hostinfo['user_list_index']
      hostinfo['user_list_index'] = hostinfo['user_list_index'] + 1

      username = hostinfo['user_list'][index]
      if(username ~= nil) then
        local _
        _, username = split_domain(username)
      end

    else
      username = hostinfo['user_list_default']()
    end

    -- Make the username lowercase (usernames aren't case sensitive, so making it lower case prevents duplicates)
    if(username ~= nil) then
      username = string.lower(username)
    end

  until username == nil or (hostinfo['invalid_usernames'][username] ~= true and hostinfo['locked_usernames'][username] ~= true and hostinfo['accounts'][username] == nil)

  return username
end

---Reset to the first username.
--
--@param hostinfo The hostinfo table.
local function reset_username(hostinfo)
  if(hostinfo['have_user_list']) then
    hostinfo['user_list_index'] = 1
  else
    hostinfo['user_list_default']("reset")
  end
end

---Do a little trick to detect account lockouts without bringing every user to the lockout threshold -- bump the lockout counter of
-- the first user ahead. If lockouts are happening, this means that the first account will trigger before the rest of the accounts.
-- A canary in the mineshaft, in a way.
--
-- The number of checks defaults to three, but it can be controlled with the <code>canary</code> argument.
--
-- Times it'll fail are when:
-- * Accounts are locked out due to the initial checks (happens if the user runs smb-brute twice in a row, the canary won't help)
-- * A valid user list isn't pulled, and we create a canary that doesn't exist (won't be as bad, though, because it means we also
--   don't have every account on the server/domain
function test_lockouts(hostinfo)
  local i
  local username = get_next_username(hostinfo)

  -- It's possible that every username was accounted for already, so our list is empty.
  if(username == nil) then
    return
  end

  if(stdnse.get_script_args( "smblockout" )) then
    return
  end

  while(string.lower(username) == "administrator") do
    username = get_next_username(hostinfo)
    if(username == nil) then
      return
    end
  end

  if(username ~= nil) then
    -- Try logging in as the "canary" account
    local canaries = nmap.registry.args.canaries
    if(canaries == nil) then
      canaries = 3
    else
      canaries = tonumber(canaries)
    end

    if(canaries > 0) then
      stdnse.debug1("Detecting server lockout on '%s' with %d canaries", username, canaries)
    end

    local result
    for i=1, canaries, 1 do
      result = check_login(hostinfo, username, get_random_string(8), "ntlm")
    end

    -- If the account just became locked (it's already been put on the 'valid' list), we're in trouble
    if(result == results.LOCKED) then
      -- If the canary just became locked, we're one step from locking out every account. Loop through the usernames and invalidate them to
      -- prevent them from being locked out
      stdnse.debug1("Canary (%s) became locked out -- aborting", username)

      -- Add it to the locked username list (so it can be reported)
      hostinfo['locked_usernames'][username] = true

      -- Mark all the usernames as invalid (a bit of a hack, but it's safer this way)
      while(username ~= nil) do
        stdnse.debug1("Marking '%s' as 'invalid'", username)
        hostinfo['invalid_usernames'][username] = true
        username = get_next_username(hostinfo)
      end
    end
  end

  -- Go back to the beginning of the list
  reset_username(hostinfo)
end

---Attempts to validate the current list of usernames by logging in with a blank password, marking invalid ones (and ones that had
-- a blank password). Determining the validity of a username works best if invalid usernames are redirected to 'guest'.
--
-- If a username accepts the blank password, a random password is tested. If that's accepted as well, the account is marked as
-- accepting any password (the 'guest' account is normally like that).
--
-- This also checks whether the server locks out users, and raises the lockout threshold of the first user (see the
-- <code>check_lockouts</code> function for more information on that. If accounts on the system are locked out, they aren't
-- checked.
--
--@param hostinfo The hostinfo table.
--@return (status, err) If status is false, err is a string corresponding to the error; otherwise, err is undefined.
local function validate_usernames(hostinfo)
  local status, err
  local result
  local username, password

  stdnse.debug1("Checking which account names exist (based on what goes to the 'guest' account)")

  -- Start a session
  status, err = restart_session(hostinfo)
  if(status == false) then
    return false, err
  end

  -- Make sure we start at the beginning
  reset_username(hostinfo)

  username = get_next_username(hostinfo)
  while(username ~= nil) do
    result = check_login(hostinfo, username, "", "ntlm")

    if(result ~= hostinfo['invalid_password'] and result == hostinfo['invalid_username']) then
      -- If the account matches the value of 'invalid_username', but not the value of 'invalid_password', it's invalid
      stdnse.debug1("Blank password for '%s' -> '%s' (invalid account)", username, result_short_strings[result])
      hostinfo['invalid_usernames'][username] = true

    elseif(result == hostinfo['invalid_password']) then

      -- If the account matches the value of 'invalid_password', and 'invalid_password' is reliable, it's probably valid
      if(hostinfo['invalid_username'] ~= results.FAIL and hostinfo['invalid_username'] == hostinfo['invalid_password']) then
        stdnse.debug1("Blank password for '%s' => '%s' (can't determine validity)", username, result_short_strings[result])
      else
        stdnse.debug1("Blank password for '%s' => '%s' (probably valid)", username, result_short_strings[result])
      end

    elseif(result == results.ACCOUNT_LOCKED) then
      -- If the account is locked out, don't try it
      hostinfo['locked_usernames'][username] = true
      stdnse.debug1("Blank password for '%s' => '%s' (locked out)", username, result_short_strings[result])

    elseif(result == results.FAIL) then
      -- If none of the standard options work, check if it's FAIL. If it's FAIL, there's an error somewhere (probably, the
      -- 'administrator' username is changed so we're getting invalid data).
      stdnse.debug1("Blank password for '%s' => '%s' (may be valid)", username, result_short_strings[result])

    else
      -- If none of those came up, either the password is legitimately blank, or any account works. Figure out what!
      local new_result = check_login(hostinfo, username, get_random_string(14), "ntlm")
      if(new_result == result) then
        -- Any password works (often happens with 'guest' account)
        stdnse.debug1("All passwords accepted for %s (goes to %s)", username, result_short_strings[result])
        status, err = found_account(hostinfo, username, "<anything>", result)
        if(status == false) then
          return false, err
        end
      else
        -- Blank password worked, but not random one
        status, err = found_account(hostinfo, username, "", result)
        if(status == false) then
          return false, err
        end
      end
    end

    username = get_next_username(hostinfo)
  end

  -- Start back at the beginning of the list
  reset_username(hostinfo)

  -- Check for lockouts
  test_lockouts(hostinfo)

  -- Stop the session
  stop_session(hostinfo)

  return true
end

---Marks an account as discovered. The login with this account doesn't have to be successful, but <code>is_positive_result</code> should
-- return <code>true</code>.
--
-- If the result IS successful, and this hasn't been done before, this function will attempt to pull a userlist from the server.
--
-- The session should be stopped before entering this function, and restarted after -- that allows this function to make its own SMB calls.
--
--@param hostinfo The hostinfo table.
--@param username The username.
--@param password The password.
--@param result   The result, as an integer constant.
--@return (status, err) If status is false, err is a string corresponding to the error; otherwise, err is undefined.
function found_account(hostinfo, username, password, result)
  local status, err

  -- Save the username
  hostinfo['accounts'][username] = {}
  hostinfo['accounts'][username]['password'] = password
  hostinfo['accounts'][username]['result']   = result

  -- Save the account (smb will automatically decide if it's better than the account it already has)
  if(result == results.SUCCESS) then
    -- Stop the connection -- this lets us do some queries
    status, err = stop_session(hostinfo)
    if(status == false) then
      return false, err
    end

    -- Check if we have an 'admin' account
    -- Try getting information about "IPC$". This determines whether or not the user is administrator
    -- since only admins can get share info. Note that on Vista and up, unless UAC is disabled, all
    -- accounts are non-admin.
    local is_admin = smb.is_admin(hostinfo['host'], username, '', password, nil, nil)

    -- Add the account
    smb.add_account(hostinfo['host'], username, '', password, nil, nil, is_admin)

    -- Check lockout policy
    local status, bad_lockout_policy_result = bad_lockout_policy(hostinfo['host'])
    if(not(status)) then
      stdnse.debug1("WARNING: couldn't determine lockout policy: %s", bad_lockout_policy_result)
    else
      if(bad_lockout_policy_result) then
        return false, "Account lockouts are enabled on the host. To continue (and risk lockouts), add --script-args=smblockout=1 -- for more information, run smb-enum-domains."
      end
    end

    -- If we haven't retrieved the real user list yet, do so
    if(hostinfo['have_user_list'] == false) then
      -- Attempt to enumerate users
      stdnse.debug1("Trying to get user list from server using newly discovered account")
      local _
      hostinfo['have_user_list'], _, hostinfo['user_list'] = msrpc.get_user_list(hostinfo['host'])
      hostinfo['user_list_index'] = 1
      if(hostinfo['have_user_list'] and #hostinfo['user_list'] == 0) then
        hostinfo['have_user_list'] = false
      end

      -- If the list was found, let the user know and reset the password list
      if(hostinfo['have_user_list']) then
        stdnse.debug1("Found %d accounts to check!", #hostinfo['user_list'])
        reset_password(hostinfo)

        -- Validate them (pick out the ones that can't possibly log in)
        validate_usernames(hostinfo)
      end
    end

    -- Start the session again
    status, err = restart_session(hostinfo)
    if(status == false) then
      return false, err
    end

  end
end

---This is the main function that does all the work (loops through the lists and checks the results).
--
--@param host The host table.
--@return (status, accounts, locked_accounts) If status is false, accounts is an error message. Otherwise, accounts
--        is a table of passwords/results, indexed by the username and locked_accounts is a table indexed by locked
--        usernames.
local function go(host)
  local status, err
  local result, hostinfo
  local password, temp_password, username
  local response = {}

  -- Initialize the hostinfo object, which sets up the initial variables
  result, hostinfo = initialize(host)
  if(result == false) then
    return false, hostinfo
  end

  -- If invalid accounts don't give guest, we can determine the existence of users by trying to
  -- log in with an invalid password and checking the value
  status, err = validate_usernames(hostinfo)
  if(status == false) then
    return false, err
  end

  -- Start up the SMB session
  status, err = restart_session(hostinfo)
  if(status == false) then
    return false, err
  end

  -- Loop through the password list
  temp_password = get_next_password(hostinfo)
  while(temp_password ~= nil) do
    -- Loop through the user list
    username = get_next_username(hostinfo)
    while(username ~= nil) do
      -- Check if it's a special case (we do this every loop because special cases are often
      -- based on the username
      if(temp_password == USERNAME) then
        password = username
        --io.write(string.format("Trying matching username/password (%s:%s)\n", username, password))
      elseif(temp_password == USERNAME_REVERSED) then
        password = string.reverse(username)
        --io.write(string.format("Trying reversed username/password (%s:%s)\n", username, password))
      else
        password = temp_password
      end

      --io.write(string.format("%s:%s\n", username, password))
      local result = check_login(hostinfo, username, password, get_type(hostinfo))

      -- Check if the username was locked out
      if(is_bad_result(hostinfo, result)) then
        -- Add it to the list of locked usernames
        hostinfo['locked_usernames'][username] = true

        -- Unless the user requested to keep going, stop the check
        if(not(stdnse.get_script_args( "smblockout" ))) then
          -- Mark it as found, which is technically true
          status, err = found_account(hostinfo, username, nil, results.ACCOUNT_LOCKED_NOW)
          if(status == false) then
            return err
          end

          -- Let the user know that it went badly
          stdnse.debug1("'%s' became locked out; stopping", username)

          return true, hostinfo['accounts'], hostinfo['locked_usernames']
        else
          stdnse.debug1("'%s' became locked out; continuing", username)
        end
      end

      if(is_positive_result(hostinfo, result)) then
        -- Reset the connection
        stdnse.debug2("Found an account; resetting connection")
        status, err = restart_session(hostinfo)
        if(status == false) then
          return false, err
        end

        -- Find the case of the password, unless it's a hash
        local case_password
        if(not(#password == 32 or #password == 64 or #password == 65)) then
          stdnse.debug1("Determining password's case (%s)", format_result(username, password))
          case_password = find_password_case(hostinfo, username, password, result)
          stdnse.debug1("Result: %s", format_result(username, case_password))
        else
          case_password = password
        end

        -- Take normal actions for finding an account
        status, err = found_account(hostinfo, username, case_password, result)
        if(status == false) then
          return err
        end
      end
      username = get_next_username(hostinfo)
    end

    reset_username(hostinfo)
    temp_password = get_next_password(hostinfo)
  end

  stop_session(hostinfo)
  return true, hostinfo['accounts'], hostinfo['locked_usernames']
end

action = function(host)

  local status, result
  local response = {}

  local username
  local usernames = {}
  local locked = {}
  local i
  local locked_result

  status, result, locked_result = go(host)
  if(status == false) then
    return stdnse.format_output(false, result)
  end

  -- Put the usernames in their own table
  for username in pairs(result) do
    table.insert(usernames, username)
  end

  -- Sort the usernames alphabetically
  table.sort(usernames)

  -- Display the usernames
  if(#usernames == 0) then
    table.insert(response, "No accounts found")
  else
    for i=1, #usernames, 1 do
      local username = usernames[i]
      table.insert(response, format_result(username, result[username]['password'], result[username]['result']))
    end
  end

  -- Make a list of locked accounts
  for username in pairs(locked_result) do
    table.insert(locked, username)
  end
  if(#locked > 0) then
    -- Sort the list
    table.sort(locked)

    -- Display the list
    table.insert(response, string.format("Locked accounts found: %s", table.concat(locked, ", ")))
  end

  return stdnse.format_output(true, response)
end

```
</p>
</details>
----------------------------------------------------



