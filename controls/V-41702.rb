# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-41702" do
  title "The web server must have Web Distributed Authoring (WebDAV) disabled."
  desc  "A web server can be installed with functionality that, just by its
nature, is not secure. Web Distributed Authoring (WebDAV) is an extension to
the HTTP protocol that, when developed, was meant to allow users to create,
change, and move documents on a server, typically a web server or web share.
Allowing this functionality, development, and deployment is much easier for web
authors.

    WebDAV is not widely used and has serious security concerns because it may
allow clients to modify unauthorized files on the web server.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployment configuration to
determine if Web Distributed Authoring (WebDAV) is enabled.

    If WebDAV is enabled, this is a finding.
  "
  desc  "fix", "Configure the web server to disable Web Distributed Authoring."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-WSR-000085"
  tag "gid": "V-41702"
  tag "rid": "SV-54279r3_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000085"
  tag "fix_id": "F-47161r2_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
  
  # dav_methods can exist in http, server, or location
  Array(nginx_conf(conf_path).params['http']).each do |http|
    # Within http
    describe 'The http context' do
      it 'should not include dav_methods.' do
        expect(http["dav_methods"]).to(be_nil)
      end
    end
    # Within server
    describe 'The server context' do
      it 'should not include dav_methods.' do
        Array(nginx_conf(conf_path).servers).each do |server|
          Array(server.params["dav_methods"]).each do |dav|       
            expect(dav).to(be_nil)
          end 
        end
      end
    end
    # Within location
    describe 'The location context' do
      it 'should not include dav_methods.' do
        Array(nginx_conf(conf_path).locations).each do |location|
          Array(location.params["dav_methods"]).each do |dav|       
            expect(dav).to(be_nil)
          end 
        end
      end
    end
  end
end

