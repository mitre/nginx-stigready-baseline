# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')
root_document_mount_path = input('root_document_mount_path')

control "V-41821" do
  title "The web server document directory must be in a separate partition from
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
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployed configuration to determine
where the document directory is located for each hosted application.

    If the document directory is not in a separate partition from the web
server's system files, this is a finding.
  "
  desc  "fix", "Configure the web server to place the document directories in a
separate partition from the web server system files."
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
    nginx_conf_handle = nginx_conf(conf_path)

    describe nginx_conf_handle do
      its ('params') { should_not be_empty }
    end

    nginx_conf_handle.http.entries.each do |http|
      webserver_roots.push(http.params['root']) unless http.params['root'].nil?
    end

    nginx_conf_handle.servers.entries.each do |server|
      webserver_roots.push(server.params['root']) unless server.params['root'].nil?
    end

    nginx_conf_handle.locations.entries.each do |location|
      webserver_roots.push(location.params['root']) unless location.params['root'].nil?
    end

    webserver_roots.flatten!
    webserver_roots.uniq!
    
    webserver_roots.each do |root|
      puts root;
      describe "Each document root defined needs to be on a separate partition from the OS." do
        it { should match /\/mnt/ }
      end
    end
end

