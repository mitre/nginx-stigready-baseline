# encoding: UTF-8

control "V-56035" do
  title "The NGINX web server must display a default hosted application web page, not
  a directory listing, when a requested web page cannot be found."
  desc  "The goal is to completely control the web user's experience in
  navigating any portion of the web document root directories. Ensuring all web
  content directories have at least the equivalent of an index.html file is a
  significant factor to accomplish this end.

    Enumeration techniques, such as URL parameter manipulation, rely upon being
  able to obtain information about the web server's directory structure by
  locating directories without default pages. In the scenario, the web server
  will display to the user a listing of the files in the directory being
  accessed. By having a default hosted application web page, the anonymous web
  user will not obtain directory browsing information or an error message that
  reveals the server type and version.
  "
  
  desc  "check", "
  Review the NGINX web server documentation and deployed configuration to locate
  all the web document directories:

    # grep for 'root' directive in each http, server, and location context of the 
    nginx.conf and any separated include configuration file.

  Verify that each web document directory contains a default hosted application web 
  page that can be used by the web server in the event a web page cannot be found:

    # Execute the 'ls' command on each directory defined in the root directive and 
    check if index.html is present for each directory.

  If a document directory does not contain a default web page (index.html), 
  this is a finding.
  "
  desc  "fix", "Add index.html file to all NGINX web document directories."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000266-WSR-000142"
  tag "gid": "V-56035"
  tag "rid": "SV-70289r2_rule"
  tag "stig_id": "SRG-APP-000266-WSR-000142"
  tag "fix_id": "F-60913r1_fix"
  tag "cci": ["CCI-001312"]
  tag "nist": ["SI-11 a", "Rev_4"]

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
    root_files = command("ls #{root}").stdout.split("\n")
    describe "The root directory #{root}" do
      it "should include the default index.html file." do
        expect(root_files).to(include 'index.html')
      end
    end
  end

  if webserver_roots.empty?
    describe 'Test skipped because the nginx root directories list is empty.' do
      skip 'This test is skipped since the nginx root directories list is empty.'
    end
  end

end

