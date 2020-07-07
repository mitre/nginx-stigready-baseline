# encoding: UTF-8

control "V-41812" do
  title "The NGINX web server must provide a clustering capability."
  desc  "The web server may host applications that display information that
  cannot be disrupted, such as information that is time-critical or
  life-threatening. In these cases, a web server that shuts down or ceases to be
  accessible when there is a failure is not acceptable. In these types of cases,
  clustering of web servers is used.

      Clustering of multiple web servers is a common approach to providing
  fail-safe application availability. To assure application availability, the web
  server must provide clustering or some form of failover functionality.
  "
  
  desc  "check", "
  Review the NGINX web server documentation, deployed configuration, and risk
  analysis documentation to verify that the web server is configured to provide
  clustering functionality, if the web server is a high-availability web server.

  If the NGINX web server is not a high-availability web server, this finding is Not Applicable.

  Enter the following command:
    # nginx -V

  This will provide a list of all loaded modules.  If the 'http_proxy_module' module is not found, this is a finding. 

  If the 'http_proxy' module is loaded and the 'proxy_pass' directive is not configured, this is a finding.
  "
  desc  "fix", "Configure the web server to provide application failover, or participate in a web cluster that provides failover for high-availability web
  servers by doing the following:
  
  Use the configure script (available in the nginx download package) to include the 'http_proxy_module' using the --with {module_name} option.
  Configure the 'proxy_pass' directive in the NGINX configuration file(s). 
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000225-WSR-000141"
  tag "gid": "V-41812"
  tag "rid": "SV-54389r3_rule"
  tag "stig_id": "SRG-APP-000225-WSR-000141"
  tag "fix_id": "F-47271r2_fix"
  tag "cci": ["CCI-001190"]
  tag "nist": ["SC-24", "Rev_4"]
  
  nginx_conf_handle = nginx_conf(input('conf_path'))

  describe nginx_conf_handle do
    its ('params') { should_not be_empty }
  end

  describe nginx do
    its('modules') { should include 'http_proxy' }
  end

  nginx_conf_handle.locations.each do |location|
    describe 'proxy_pass' do
      it 'should be configured in the location context.' do
        expect(location.params).to(include "proxy_pass")
      end
    end
  end
end

