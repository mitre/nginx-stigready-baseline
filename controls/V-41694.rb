# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-41694" do
  title "The web server must not be a proxy server."
  desc  "A web server should be primarily a web server or a proxy server but
not both, for the same reasons that other multi-use servers are not
recommended.  Scanning for web servers that will also proxy requests into an
otherwise protected network is a very common attack making the attack
anonymous."
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployed configuration to determine
if the web server is also a proxy server.

    If the web server is also acting as a proxy server, this is a finding.
  "
  desc  "fix", "
    Uninstall any proxy services, modules, and libraries that are used by the
web server to act as a proxy server.

    Verify all configuration changes are made to assure the web server is no
longer acting as a proxy server in any manner.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-WSR-000076"
  tag "gid": "V-41694"
  tag "rid": "SV-54271r3_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000076"
  tag "fix_id": "F-47153r3_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]

  describe nginx do
    its('modules') { should_not include 'ngx_http_proxy_module' }
  end

  Array(nginx_conf(conf_path).locations).each do |location|
    describe 'proxy_pass' do
      it 'should not exist in the location context.' do
        expect(location.params).to_not(include "proxy_pass")
      end
    end
  end
end

