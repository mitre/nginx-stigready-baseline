# encoding: UTF-8


control "V-41821" do
  title "The NGINX web server document directory must be in a separate partition from
the web servers system files."
  desc  "A web server is used to deliver content on the request of a client.
The content delivered to a client must be controlled, allowing only hosted
application files to be accessed and delivered. To allow a client access to
system files of any type is a major security risk that is entirely avoidable.
Obtaining such access is the goal of directory traversal and URL manipulation
vulnerabilities. To facilitate such access by misconfiguring the web document
(home) directory is a serious error. In addition, having the path on the same
drive as the system folder compounds potential attacks such as drive space
exhaustion."
  
  desc  "check", "Review the NGINX web server documentation and deployed configuration 
  to determine where the document directory is located for each hosted application.

  Check for the following:

    #grep the 'root' directive in the http, server, and location context of the nginx.conf and any separated include configuration file.

  If the path for any of the directives is on the same partition as the web server operating system files, this is a finding.
  "
  desc  "fix", "Create and mount a new partition. 
  Once partition is created, the directory needs to be copied over using the following command:
    # sudo rsync -av <DOCUMENT HOME DIRECTORY> <NEW MOUNTED PARTITION>.
  
  Update the 'root' directives in the NGINX configuration file(s) with the new location."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000233-WSR-000146"
  tag "gid": "V-41821"
  tag "rid": "SV-54398r3_rule"
  tag "stig_id": "SRG-APP-000233-WSR-000146"
  tag "fix_id": "F-47280r2_fix"
  tag "cci": ["CCI-001084"]
  tag "nist": ["SC-3", "Rev_4"]

  
    # collect root directores from nginx_conf
    webserver_roots = []

    nginx_conf.http.entries.each do |http|
      webserver_roots.push(http.params['root']) unless http.params['root'].nil?
    end

    nginx_conf.servers.entries.each do |server|
      webserver_roots.push(server.params['root']) unless server.params['root'].nil?
    end

    nginx_conf.locations.entries.each do |location|
      webserver_roots.push(location.params['root']) unless location.params['root'].nil?
    end

    webserver_roots.flatten!
    webserver_roots.uniq!
    
    webserver_roots.each do |root|
      describe "The root directory #{root}" do
        it { should_not cmp '/'}
      end
    end

    if webserver_roots.empty?
      describe 'Test skipped because the nginx root directory list is empty.' do
        skip 'This test is skipped since the nginx root directory list is empty.'
      end
    end 
end

