description = [[
Checks if a website is running Drupal and possibly detect it's version.
]]

---
-- @args http-drupal-fingerprint.base-url The base folder for the website. Defaults to
-- <code>/</code>.
--
-- @usage
-- nmap --script=http-drupal-fingerprint.nse --script-args http-drupal-fingerprint.base-url=/website/ <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-drupal-fingerprint: 
-- |_Drupal 6.19

author = "Hani Benhabiles"
edited = "tacticthreat"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}


shortport = require 'shortport'
http = require 'http'
stdnse = require 'stdnse'
pcre = require 'pcre'

portrule = shortport.http

--These are common Drupal websites fingerprints
local drupal_fingerprints = 
    { [[Drupal.settings, { "basePath]], [[/drupal.js?]], 
      ' src="/sites/all/themes/', ' href="/sites/all/themes/', 
      ' src="/sites/all/modules/' }

--These are common Drupal websites files
local drupal_files = 
    { "COPYRIGHT.txt", "UPGRADE.txt", "LICENSE.txt", "MAINTENERS.txt", 
     "INSTALL.txt", "INSTALL.mysql.txt", "INSTALL.pgsql.txt", "install.php",
     "update.php" }

--- Detects Drupal version from CHANGELOG.txt body
--@param changelog content of CHANGELOG.txt file
local function drupal_changelog(changelog)    
    local expression = "Drupal [4-7].[0-9][0-9]?.?[0-9], "
    local regex = pcre.new(expression, 0, "C")
    local limit, limit2, matches = regex:match(changelog)

    if limit ~= nil then
        -- Found "Drupal x.x[x].[x], "
        return changelog:sub(limit+7,limit2-2)
    end
end

--- put id in the nmap registry for usage by other scripts
--@param host nmap host table
--@param port nmap port table
--@param base_url the base url for the website. "/" by default.
local function drupal_fingerprint(host, port, base_url)
    local version = nil
    local fingerprints = {}
    
    -- Drupal detection using fingerprints table
    local response = http.get(host, port, base_url)
    for keys, finger in pairs(drupal_fingerprints) do
        if string.find(response.body, finger) then
	    table.insert(fingerprints, finger)
        end
    end
    -- Drupal detection using drupal_files table
    for _, file in pairs(drupal_files) do
        response = http.get(host, port, base_url .. file)

        -- following redirection
        if response.header.location then
            response = http.get(host, port, response.header.location)
        end
        if string.find(response.body,"Drupal ") then
            table.insert(fingerprints, file)
        end
    end

   -- Drupal version with CHANGELOG.txt file
    local changelog = http.get(host, port, base_url .. "CHANGELOG.txt")
    if changelog.status == 200 and string.find(changelog.body,"Drupal ")then
	table.insert(fingerprints, "CHANGELOG.txt")
        version = drupal_changelog(changelog.body)
    end

   return version, fingerprints
end

action = function(host, port)

    local base_url = stdnse.get_script_args("http-drupal-fingerprint.base-url") or "/"
    local Drupal_version,Drupal_fingerprints = drupal_fingerprint(host, port, base_url)

    if #Drupal_fingerprints > 0 then

        -- Debug
        stdnse.print_debug (1, "Drupal fingerprints")        
        for _,fingerprint in pairs(Drupal_fingerprints) do
            stdnse.print_debug (1, fingerprint)        
        end
        return "\nDrupal ".. (Drupal_version or "unknown version")
    end 
end
