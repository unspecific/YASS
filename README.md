# YASS

# http-scan.pl (not just for HTTP anymore)</div>
<div class=mainbody>
<center>If you want information about new releases mailed to you,<br> or have any suggestions, please contact <a href=mailto:madhat@unspecific.com>me</a>.</center><br>
Quick note, with the latest version, there are the kind of numbers I am getting doing a full scan.<br>
<pre>Scan of 46721 ip(s) took 8794 seconds
Of 46721 ip(s), 5717 are listening to port 80
5.3 ips/sec - 0.7 hosts/sec
</pre>
This was on a 600MHz FreeBSD box with 256Mb RAM.
<br clear=all>
<small><center><hr size=1 width=80% noshade><a href=#desc>Description</a> | <a href=#feat>Features</a> | <a href=#bugs>Bugs</a> | <a href=#todo>ToDo</a> | <a href=#requi>Requirements</a> | <a href=#down>Download</a> | <a href=#out>Output</a> | <a href=#use>Usage/Docs</a> | <a href=#goals>Goals</a> | <a href=#change>Change Log</a><hr size=1 width=80% noshade></center></small>

<a name=desc>
<h2>Description</h2>
Written by: <a href=mailto:madhat@unspecific.com>MadHat at Unspecific.com</a><br>
Yet Another Web/HTTP Scanner...<br><br>
<blockquote>
This is a HTTP scanner than can do some really nifty things and is simple to use.  I tried to make it as fast as possible to be able to scan large numbers of hosts in short time frames with as few false positives as possible.  The config file is in XML, and it is easy to add new scans with a fair amount of flexibility.  This flexibility allows for fewer false positives and makes the scanner easier to extend beyond what is included here, without having to write code.
<br><br>
<li>Added to this is now an FTP scanner that looks for anonymous FTP access, and checks for writablility.
<br><br>
<li>Also added is a SQL scanner that looks for MS-SQL boxes that are vuln to the SLAPPER worm.  More tests will be added later.
<br><br>
<li>Both of the new scan type have been added to show the ability to use the same code base for many types of scanners, not just http.  New rules will be added to the XML as I figure out how I want to add these rules and what we want to look for.
<br><br>
</blockquote>

<small><center><hr size=1 width=80% noshade><a href=#desc>Description</a> | <a href=#feat>Features</a> | <a href=#bugs>Bugs</a> | <a href=#todo>ToDo</a> | <a href=#requi>Requirements</a> | <a href=#down>Download</a> | <a href=#out>Output</a> | <a href=#use>Usage/Docs</a> | <a href=#goals>Goals</a> | <a href=#change>Change Log</a><hr size=1 width=80% noshade></center></small>
<a name=feat>
<h2>Features</h2>
<ul>
<li> <b>Fast</b>.  One of the main goals was to make this fast.  I was tired of using scanners that try ever vulnerability on every box, even if the port isn't open.<br>
- To try and make this faster, it uses some basic threading (forking child processes actually).  You can control the number of active children, default is 32.<br>
- Also I have added in where it will only check vulnerabilities when the banner matches (can be overridden with -a), not always the best thing since we all know the banners can be changed and hidden, but how many IIS admins do you know that change their banners?<br><br>
<li> <b>Extensible</b> (I think that is what I mean).  Using the XML config file it is easy to add more tests, whether they are actual exploits, or just looking for specific pages.  Simple format.<br><br>
<li> <b>Easy</b>  Put this in your cgi-bin and it is GUI (all the rage with the kids these days).  Or do everything from commandline.  Nice and easy.<br>
<a href=http-scan.pl.html>Sample of Web Interface</a> - On the real thing, the config file is used to show available scans.  This is just a sample, <b>IT DOES NOT WORK</b>.<br><br>
<li> <b>Configurable</b> Do simple banner-grabbing, or run a whole set of tests on one or thousands of hosts.  Look for specific strings on web pages and look for last modified dates.  Test for specific versions (if reported by the banner).  Not just a simple "Run These Tests" scanner.<br><br>
<li> <b>Accurate</b>  One of the things that always pissed me off about many of the scanners out there was the large number of false positives.  I do my best to weed out the false positives by looking for specific return codes, detecting custom 404 pages, and redirects.  Also being able to scan the returned page/text for specific strings to compare.

</ul>

<small><center><hr size=1 width=80% noshade><a href=#desc>Description</a> | <a href=#feat>Features</a> | <a href=#bugs>Bugs</a> | <a href=#todo>ToDo</a> | <a href=#requi>Requirements</a> | <a href=#down>Download</a> | <a href=#out>Output</a> | <a href=#use>Usage/Docs</a> | <a href=#goals>Goals</a> | <a href=#change>Change Log</a><hr size=1 width=80% noshade></center></small>
<a name=bugs>
<h2>BUGS</h2>
Send your bugs to <a href=mailto:bugs@unspecific.com>Bugs at Unspecific.com</a><br>
<ul>
  <li> SMTP Vuls are not accurate.  The Net::SMTP is not designed for this.  A complete rewrite is being done.
  <li> Issues with CSS/Javascript with Netscape pre ver 6
</ul>

<small><center><hr size=1 width=80% noshade><a href=#desc>Description</a> | <a href=#feat>Features</a> | <a href=#bugs>Bugs</a> | <a href=#todo>ToDo</a> | <a href=#requi>Requirements</a> | <a href=#down>Download</a> | <a href=#out>Output</a> | <a href=#use>Usage/Docs</a> | <a href=#goals>Goals</a> | <a href=#change>Change Log</a><hr size=1 width=80% noshade></center></small>
<a name=todo>
<h2>ToDo</h2>
<ul>
<li> Update the CGI interface
<li> Add capability to pull default settings (i.e. port, debug level, output method, etc...) from the config (already added to the config, just not used at this time).
<li> <em>Done</em>Fix NBT lookups when UDP 137 is available, but not have to wait for timeouts or deal with crappy 'die' messages.
<li> <em>Done</em> - <small>Fix the SSL support</small>
</ul>

<small><center><hr size=1 width=80% noshade><a href=#desc>Description</a> | <a href=#feat>Features</a> | <a href=#bugs>Bugs</a> | <a href=#todo>ToDo</a> | <a href=#requi>Requirements</a> | <a href=#down>Download</a> | <a href=#out>Output</a> | <a href=#use>Usage/Docs</a> | <a href=#goals>Goals</a> | <a href=#change>Change Log</a><hr size=1 width=80% noshade></center></small>
<a name=requi>
<h2>Requirements</h2>
<ul>
<li><a href=http://www.perl.com>Perl</a> >= 5.6 <br>
<li><a href=http://search.cpan.org/search?dist=CGI.pm>CGI</a><br>
<li><a href=http://search.cpan.org/search?dist=libwww-perl>LWP::UserAgent</a><br>
<li><a href=http://search.cpan.org/search?dist=Time-HiRes>Time::HiRes</a><br>
<li><a href=http://search.cpan.org/search?dist=Crypt-SSLeay>Crypt::SSLeay</a><br>
<li><a href=http://search.cpan.org/author/SAMPO/Net_SSLeay.pm-1.20/>Net::SSLeay</a><br>
<li><a href=http://search.cpan.org/search?dist=XML-Simple>XML::Simple</a> ( which requires <a href=http://search.cpan.org/search?dist=XML-Parser>XML::Parser</a> and <a href=http://sourceforge.net/projects/expat/>expat</a>)<br>
<li><a href=http://search.cpan.org/author/GBARR/libnet-1.12/Net/FTP.pm>Net::FTP</a> which is part of <a href=http://search.cpan.org/author/GBARR/libnet-1.12/>libnet</a>
</ul>


<small><center><hr size=1 width=80% noshade><a href=#desc>Description</a> | <a href=#feat>Features</a> | <a href=#bugs>Bugs</a> | <a href=#todo>ToDo</a> | <a href=#requi>Requirements</a> | <a href=#down>Download</a> | <a href=#out>Output</a> | <a href=#use>Usage/Docs</a> | <a href=#goals>Goals</a> | <a href=#change>Change Log</a><hr size=1 width=80% noshade></center></small>
<a name=down>
<h2>Download</h2>
<ul>
<li><a href=http-scan.pl>http-scan.pl</a> v3.5.5 - the script itself<br><br>
<li><a href=http-scan.xml>http-scan.xml</a> v2.07 - the config file<br><br>
<li><a href=http-scan.tgz>http-scan.tgz</a> - both files in one tgz in a http-scan directory<br><br>
</ul>

<small><center><hr size=1 width=80% noshade><a href=#desc>Description</a> | <a href=#feat>Features</a> | <a href=#bugs>Bugs</a> | <a href=#todo>ToDo</a> | <a href=#requi>Requirements</a> | <a href=#down>Download</a> | <a href=#out>Output</a> | <a href=#use>Usage/Docs</a> | <a href=#goals>Goals</a> | <a href=#change>Change Log</a><hr size=1 width=80% noshade></center></small>
<a name=out>
<h2>Output</h2>
<pre>
<b> Basic Scan</b>
madhat@avatar $ ./http-scan.pl -v -l 10.0.0.0/24 -f http-scan.xml
scanning 10.0.0.0/24

10.0.0.6 (NOT_IN_DNS) 80
10.0.0.6 tcp 80 - Apache/1.3.23 (Unix) mod_ssl/2.8.7 OpenSSL/0.9.6a - 
  Running vulnerable Apache - 

10.0.0.150 (NOT_IN_DNS) 80
10.0.0.150 tcp 80 - Microsoft-IIS/4.0 - /_vti_bin/shtml.dll file access - 
10.0.0.150 tcp 80 - Microsoft-IIS/4.0 - FrontPage extention htimage.exe - 
10.0.0.150 tcp 80 - Microsoft-IIS/4.0 - FrontPage extention imagemap.exe - 
10.0.0.150 tcp 80 - Microsoft-IIS/4.0 - IIS acdg.htr mapping _AuthChangeUrl? - 
10.0.0.150 tcp 80 - Microsoft-IIS/4.0 - IIS password brute iisadmpwd/achg.htr - 
10.0.0.150 tcp 80 - Microsoft-IIS/4.0 - IIS password brute iisadmpwd/aexp.htr - 
10.0.0.150 tcp 80 - Microsoft-IIS/4.0 - IIS password brute iisadmpwd/aexp2.htr - 
10.0.0.150 tcp 80 - Microsoft-IIS/4.0 - IIS password brute iisadmpwd/aexp2b.htr - 
10.0.0.150 tcp 80 - Microsoft-IIS/4.0 - IIS password brute iisadmpwd/aexp3.htr - 
10.0.0.150 tcp 80 - Microsoft-IIS/4.0 - IIS password brute iisadmpwd/aexp4.htr - 
10.0.0.150 tcp 80 - Microsoft-IIS/4.0 - IIS password brute iisadmpwd/aexp4b.htr - 
10.0.0.150 tcp 80 - Microsoft-IIS/4.0 - IIS password brute iisadmpwd/anot.htr - 
10.0.0.150 tcp 80 - Microsoft-IIS/4.0 - IIS password brute iisadmpwd/anot3.htr - 
10.0.0.150 tcp 80 - Microsoft-IIS/4.0 - MSADC / showcode.asp - 
10.0.0.150 tcp 80 - Microsoft-IIS/4.0 - _vti_bin/fpcount.exe Buffer Overflow - 
10.0.0.150 tcp 80 - Microsoft-IIS/4.0 - msadc.dll vuln - 
10.0.0.150 tcp 80 - Microsoft-IIS/4.0 - webhits.dll arbitrary file access - 

10.0.0.204 (NOT_IN_DNS) 80
10.0.0.204 tcp 80 - Microsoft-IIS/5.0 - UniCode Exploit from /scripts %255c - 
10.0.0.204 tcp 80 - Microsoft-IIS/5.0 - webhits.dll arbitrary file access - 

--
Scan Finished.
Scan took 25 seconds

<hr>
<b> Banner Grabbing</b>
madhat@avatar $ ./http-scan.pl -N -v -l 172.21.128.128/25
Scanning the default webpage looking for versioning info
scanning 172.21.128.128/25
172.21.128.168 (NOT_IN_DNS) 80
172.21.128.168 tcp 80 - ALICE - Microsoft-IIS/5.0 - Restricted Access(403) -

172.21.128.189 (march-hare.unspecific.com) 80
172.21.128.189 tcp 80 - MARCH-HARE - Oracle HTTP Server Powered by 
  Apache/1.3.12 (Win32) ApacheJServ/1.1 mod_ssl/2.6.4 OpenSSL/0.9.5a 
  mod_perl/1.24 - Version Info -

172.21.128.181 (NOT_IN_DNS) 80
172.21.128.181 tcp 80 - WHITE-RABBIT - Microsoft-IIS/5.0 - Version Info -

172.21.128.230 (madhat.unspecific.com) 80
172.21.128.230 tcp 80 -  - Apache/1.3.26 - Version Info -


--
Scan Finished.
Scan of 128 ip(s) took 21 seconds
Of 128 ip(s), 5 are listening to port 80
6.1 ips/sec - 0.2 hosts/sec

<hr>
</pre>

<a href=http-scan.pl.html>Sample of Web Interface</a> - On the real thing, the config file is used to show available scans.  This is just a sample, <b>IT DOES NOT WORK</b>.<br><br>

<small><center><hr size=1 width=80% noshade><a href=#desc>Description</a> | <a href=#feat>Features</a> | <a href=#bugs>Bugs</a> | <a href=#todo>ToDo</a> | <a href=#requi>Requirements</a> | <a href=#down>Download</a> | <a href=#out>Output</a> | <a href=#use>Usage/Docs</a> | <a href=#goals>Goals</a> | <a href=#change>Change Log</a><hr size=1 width=80% noshade></center></small>
<a name=use>
<h2>Usage (output from ./http-scan.pl -h)</h2>
<pre>
$ ./http-scan.pl

 : http-scan v3.0.0 - MadHat (at) Unspecific.com
 : http://www.unspecific.com/scanner

./http-scan.pl < -hmNFsavUD > -i <filename> |  -l <host_list> \
         [ -o <filename>] [ -t <timeout>] [ -M <method> ] \
         [ -f <rules_file>] [ -u <URI_Query>] \
         [ -n <num_children>] [ -p <port_num>] \
         [ -e <expression>] \   <=== can be regex
         [ -d <debug_level>] [ -T ScanType ]
options:
  -h   help (this stuff)
  -a   force scan ALL checks regardless of version
  -s   use SSL (sets port to 443, unless -p is given) BUGGY
  -m   Show Last-modified date when a match is found
  -N   Lookup NetBIOS name using NBT (requires 137/udp access)
  -F   Show FIX with results
  -T   Only scan with certain scans (Proxy, PUT, DELETE, Apache, Microsoft)
  -v   verbose - will add details
  -d   add debuging info (value 1-3)
    1 - info on current location in scans (STDERR)
    2 - more detailed info on scans, added to above on STDOUT or -o
    3 - annoying output, same as above, with all data return from host to STDOUT or -o
  -f   XML rules file that contains vulns to search for
  -l   network list in comma delimited form: a.b.c.d/M,e.f.g.h/x.y.z.M
  -i   input file containing network list, one network per line
  -u   URL to look for on each host
       can not be used with conf file
  -e   Perl regular expression to match
       if no -e is set, verification that the page exists
       can not be used with conf file
  -n   max number of children to fork
  -p   port number to scan for vulns on
  -t   timeout (in seconds)
  -w   what scan to use, valid options are http, ftp, sql, and all
       This is allowing me to add new scan types on the same frontend
       Web interface defaults to 'all'
       'ftp' look for FTP servers and anonymous access as well as wratability
       'sql' looks for vulnerable MS SQL servers right now, thanks SLAPPER
  -D   Disguise the 'User-Agent' as a regular browser
  -U   Update the config file (fetch a new version)
  -M   Method to use, i.e. GET, HEAD, OPTIONS, etc... 
       PUT and POST not 100% supported (yet)
       can not be used with conf file
  -o   output file

<hr>

The host list can be a set of host names, comma separated, or ip, or subnets
in one of the following formats:

       a.b.c.d/n       - 10.0.0.1/25
       a.b.c.*         - 10.0.0.* (0-255) same as /24
       a.b.c.d/w.x.y.z - 10.0.0.0/255.255.224.0 (standard format)
       a.b.c.d/w.x.y.z - 10.0.0.0/0.0.16.255    (cisco format)
       a.b.c.d-z       - 10.1.2.0-12
       a.b.c-x.*       - 10.0.0-3.*  (last octet has to be * or 0)
       a.b.c-x.d       - 10.0.0-3.0
       hostname        - www.unspecific.com


</pre>
<small><center><hr size=1 width=80% noshade><a href=#desc>Description</a> | <a href=#feat>Features</a> | <a href=#bugs>Bugs</a> | <a href=#todo>ToDo</a> | <a href=#requi>Requirements</a> | <a href=#down>Download</a> | <a href=#out>Output</a> | <a href=#use>Usage/Docs</a> | <a href=#goals>Goals</a> | <a href=#change>Change Log</a><hr size=1 width=80% noshade></center></small>
<a name=goals>
<h2>Goals</h2>
<ol>
   <li> Clean up debug output.
        <ul>
          <li> Level 1: simple location (i.e. the $0 changes) within the script written to STDERR
          <li> Level 2: Level 1 + steps taken written output file (default is STDOUT)
          <li> Level 3: Level 2 + input and output from each request made written output file (default is STDOUT)
        </ul>
   <li> Clean up HTML output and add HTML out as command line option
   <li> Add XML output for easier input into databases or other scripts *wink*wink*
   <li> Still have a false positive I found recently to fix.
</ol>
<br><br>

<small><center><hr size=1 width=80% noshade><a href=#desc>Description</a> | <a href=#feat>Features</a> | <a href=#bugs>Bugs</a> | <a href=#todo>ToDo</a> | <a href=#requi>Requirements</a> | <a href=#down>Download</a> | <a href=#out>Output</a> | <a href=#use>Usage/Docs</a> | <a href=#goals>Goals</a> | <a href=#change>Change Log</a><hr size=1 width=80% noshade></center></small>
<a name=change>
<h2>Change Log</h2>
<ul> 
  <li><b>3.5</b> (3.4 was internal testing and did not get released)
  <ul>
    <li> added the -w and seperate can types, current options include ftp, for an FTP scanner that looks for anonymouse and writable FTP servers<br>sql that looks for MS SQL servers vulnerable to the SLAPPER worm and http and all, defaults to http or bases on the command line exec name (i.e. http-scan would be the http scanner, symlink it is sql-scan and it will use the sql scanner).
    <li> added more debug info at startup and run time.  Trying to make sure it all works the way expected.
    <li> added some HTML processing to try and detect JavaScript onLoad redirects to keep from spewing out.
    <li> fixed a problem in the process management side of things, it actually works now and will keep -n number of processes running at any point in time.
    <li> a lot of reordering of code.
    <li> properly identify Streaming servers, like Real and Windows Media
    <li> added MD5 page verification of some pages for fewer false positives.  Adding more as I have a chance to find vulnerable servers ;)
    <li> 
  </ul>
  <li><b>3.3</b>
  <ul>
    <li> some housework here and there
    <li> added fingerprinting of web server via OPTIONS and the order and options available.  Needs more work, but works.
    <li> added the ability to scan specific scans via the ID number.  Check boxes in the GUI web interface, -S for the CLI.  -S#,#,#
    <li> added ability to list the scans via the CLI with -L, will be cleaning up the output of that shortly
    <li> modulerized some items to reduce number of lines overall (in a way)
    <li> added more CSS stuff on the Web interface for explanations and fixes for the vulnerabnilities.  Still looks usable in lynx as well.<br> Works with Mozilla, Opera, MSIE and Netscape6.  BUGs with Netscape&lt;6
    <li> several updates on the XML config, like adding description info, CVE, new scans, and fingerprinting info.
    <li> fixed some small issues with the RAW Request sub routine (Socket connection used to test some vulnerabilities rather than LWP)
  </ul>
  <li><b>3.2</b>
  <ul>
    <li> Fixed problem with RegEx finding false positives and not finding real vulns because of special characters
    <li> Added some new vulns to the XML DB (v.1.30)
    <li> fixed some timeout issues and proper eval for testing sockets, using sslcat from Net::SSLeay for 'raw' ssl requests
    <li> added new catch for some vulns (like XSS vuln found in 403 error messages)
    <li> added better sigs for some vulns
    <li> Added -M option for simple (not using a conf file) check to allow for Method of request.  
    <li> added above to the HTML GUI interface
    <li> Added ability to use any Method in the conf file
    <li> Added %HOST% to raw requests to be able to send "Host: ip" in the headers
    <li> fixed output problem with HTML output (converted &lt; to &anp;lt; so you see the HTML, instead of the rendered page when debuging)
    <li> added new stat of the number of matches to a scan or vulns found
    <li> started added more comments to the code ;)
    <li> added new inputtype for hosts<br>
<blockquote><code>http-scan.pl -v -l name[100-132].domain.com</code><br>
<code>http-scan.pl -v -s -f http-scan.xml -l name[01-22].domain.com</code></blockquote><br>
  </ul>
  <li><b>3.1</b>
  <ul>
    <li> fixed a problem with trying to determine version too often
    <li> fixed SSL support
    <li> added a 'fix' for false positives on MS vulns
    <li> added UNKNOWN on output of Version info if version can not be determined from the header or body or status page
    <li> updated the PUT test to include more info about what the file is
    <li> cleaned up more of the debugging
    <li> made the stats when using -v more accurate
  </ul>
  <li> <b>3.0</b>
  <ul>
    <li>  fixed and re added the -N option for grabbing NetBIOS name when UDP 137 is available
    <li>  Fixed some signaling issues with counting open ports, so now we have stats of IPs/sec, total number of listeners and hosts 'scanned'/sec.
    <li>  added -Oh for HTML output and cleaned the HTML output up
  </ul>

  <li> <b>2.5.0</b>
  <ul>
    <li> I think I finally fixed the forking problems.  I am sure its not the cleanest way of do things, but it does appear to work now.
    <li> Cleaned up debug output, levels are set now.  I am not able to run something like this:
   <code>./http-scan.pl -v -l 10.1.0.0/24 -f ./http-scan.xml -d 1 | mail -s '10.1.0.0/24 Scan' madhat@unspecific.com</code>
    and the results will be sent to me like normal, but the STDERR debug info is printed to the screen so I can see where the script is.
    <li> fixed a logic error in testing for some false positives using the Content-Type header
    <li> fixed an error when testing for Version info, it was in wrong location
    <li> created some new global variables for options.  Like set the status page, where it will look for version info if it can't find it in the header fields. (think Apache /status page)
    <li> Changed version scan or simple 'does it exist' scans to use HEAD instead of GET to cut back on logging.  If you are expecting anything, it will do a GET to 'get' the content of the page, not just the Return-Code
    <li> Better naming of the 'vuln name' when scanning by command line (inputing URL and expect on the CLI)
    <li>  Added 'Content' to the add_host and DEBUG lvl 3, so you can see specifically what is returned to verify and/or debug.
    
  </ul>

<small><center><hr size=1 width=80% noshade><a href=#desc>Description</a> | <a href=#feat>Features</a> | <a href=#bugs>Bugs</a> | <a href=#todo>ToDo</a> | <a href=#requi>Requirements</a> | <a href=#down>Download</a> | <a href=#out>Output</a> | <a href=#use>Usage/Docs</a> | <a href=#goals>Goals</a> | <a href=#change>Change Log</a><hr size=1 width=80% noshade></center></small>
