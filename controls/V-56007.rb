# encoding: UTF-8
conf_path = input('conf_path')

control "V-56007" do
  title "Cookies exchanged between the web server and the client, such as
session cookies, must have cookie properties set to prohibit client-side
scripts from reading the cookie data."
  desc  "A cookie can be read by client-side scripts easily if cookie
properties are not set properly. By allowing cookies to be read by the
client-side scripts, information such as session identifiers could be
compromised and used by an attacker who intercepts the cookie. Setting cookie
properties (i.e. HttpOnly property) to disallow client-side scripts from
reading cookies better protects the information inside the cookie."
  desc  "rationale", ""
  desc  "check", "
  Review the NGINX web server documentation and deployed configuration to determine
  how to disable client-side scripts from reading cookies.

  If it is determined that the web server is not required to perform session 
  management, this check is Not Applicable. 

  Check for the following: 
    # grep the 'proxy_cookie_path' directive in the location context of the 
    nginx.conf and any separated include configuration file.
  
  If the 'proxy_cookie_path' directive exists and is not set to the 'HTTPOnly' 
  property, this is a finding.
  "
  desc  "fix", "
  If the 'proxy_cookie_path' directive exists in the NGINX configuration file(s), 
  configure it to include the 'HTTPOnly' property. 

  Example:
  proxy_cookie_path / '/; HTTPOnly; Secure'"
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000439-WSR-000154"
  tag "gid": "V-56007"
  tag "rid": "SV-70261r2_rule"
  tag "stig_id": "SRG-APP-000439-WSR-000154"
  tag "fix_id": "F-60885r1_fix"
  tag "cci": ["CCI-002418"]
  tag "nist": ["SC-8", "Rev_4"]

  nginx_conf_handle = nginx_conf(conf_path)

  describe nginx_conf_handle do
    its ('params') { should_not be_empty }
  end

  Array(nginx_conf_handle.locations).each do |location|
    values = []
    values.push(location.params['proxy_cookie_path'])
    describe "The 'proxy_cookie_path'" do
      it 'should be configured to HTTPOnly and Secure' do
        expect(values.to_s).to(include "/; HTTPOnly; Secure") 
      end unless location.params['proxy_cookie_path'].nil?
    end
  end
end

