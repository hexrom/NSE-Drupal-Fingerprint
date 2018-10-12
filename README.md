# NSE-Drupal-Fingerprint
Checks if a website is running Drupal and possibly detect it's version.

### Usage
nmap --script=http-drupal-fingerprint.nse --script-args http-drupal-fingerprint.base-url=/website/ <target>

@args http-drupal-fingerprint.base-url The base folder for the website. Defaults to <code>/</code>.

@output  
-- PORT   STATE SERVICE  
-- 80/tcp open  http  
-- | http-drupal-fingerprint:   
-- |_Drupal 6.19  

Author:    
Hani Benhabiles  
Edited by:  
r3dh4nds

