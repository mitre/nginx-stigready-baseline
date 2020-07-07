# encoding: UTF-8

control "V-41694" do
  title "The NGINX web server must not be a proxy server."
  desc  "A web server should be primarily a web server or a proxy server but
  not both, for the same reasons that other multi-use servers are not
  recommended.  Scanning for web servers that will also proxy requests into an
  otherwise protected network is a very common attack making the attack
  anonymous."
  
  desc  "check", "Review the NGINX web server documentation and deployed 
  configuration to determine if the web server is also a proxy server.

  If the NGINX server is a proxy server and not a web server, this check is Not Applicable.

  Execute the following command: 

  # nginx -V

  Verify the ‘nginx_http_proxy_module’ module is not installed.

    # grep the 'proxy_pass' directive in the location context of the  nginx.conf and any 
    separated include configuration file.

  If the 'nginx_http_proxy_module' module is installed and the 'proxy_pass' directive exists, 
  this is a finding. 
  "
  desc  "fix", "
  Use the configure script (available in the nginx download package) to exclude the 
  'nginx_http_proxy_module' module by using the --without {module_name} option. 

  Ensure the 'proxy_pass' directive is not enabled in the NGINX configuration file(s).   
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

  nginx_conf_handle = nginx_conf(input('conf_path'))

  describe nginx_conf_handle do
    its ('params') { should_not be_empty }
  end
  describe nginx do
    its('modules') { should_not include 'http_proxy' }
  end

  nginx_conf_handle.locations.each do |location|
    describe 'proxy_pass' do
      it 'should not exist in the location context.' do
        expect(location.params).to_not(include "proxy_pass")
      end
    end
  end
end

