#  NMAP & Its useful cheatsheet
## User manual &amp; top nse scripts of NMAP
------------------------------------------
#### Nmap (“Network Mapper”) is a free and open-source utility for network discovery and security auditing. Many systems and network administrators also find it useful for tasks such as network inventory, managing service upgrade schedules, and monitoring host or service uptime. It uses raw IP packets in novel ways to determine what hosts are available on the network, what services (application name and version) those hosts are offering, what operating systems (and OS versions) they are running, what type of packet filters/firewalls are in use, and dozens of other characteristics.
------------------------------------------
#### Basic Syntax:<br />
#### ``` nmap [Scan Type] [Options] {targe specification} ```
------------------------------------------

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

---------------------------------------------------
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
----------------------------------------------------
  
## 3. name.nse

##### General Description
```
Categories: will be added
Download: will be added
```
<details><summary>name.nse</summary>
<p>
  
```lua
will be added
```
</p>
</details>
----------------------------------------------------
  
## 4. name.nse

##### General Description
```
Categories: will be added
Download: will be added
```
<details><summary>name.nse</summary>
<p>
  
```lua
will be added
```
</p>
</details>
----------------------------------------------------
  
## 5. name.nse

##### General Description
```
Categories: will be added
Download: will be added
```
<details><summary>name.nse</summary>
<p>
  
```lua
will be added
```
</p>
</details>
----------------------------------------------------

