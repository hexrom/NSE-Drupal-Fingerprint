# NSE-Drupal-Fingerprint
Checks if a website is running Drupal and possibly detect it's version.

### Install
`curl -ksL https://raw.githubusercontent.com/tacticthreat/NSE-Drupal-Fingerprint/master/http-drupal-fingerprint.nse >> /usr/share/nmap/scripts/http-drupal-fingerprint.nse && chmod 0644 /usr/share/nmap/scripts/http-drupal-fingerprint.nse`

### Usage
`nmap --script=http-drupal-fingerprint.nse --script-args http-drupal-fingerprint.base-url=/website/ <target>`

@args http-drupal-fingerprint.base-url The base folder for the website. Defaults to <code>/</code>.

@output  
-- PORT   STATE SERVICE  
-- 80/tcp open  http  
-- | http-drupal-fingerprint:   
-- |_Drupal 6.19  


This is an edited version of https://seclists.org/nmap-dev/2011/q2/490
