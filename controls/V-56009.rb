# encoding: UTF-8

control "V-56009" do
  title "Cookies exchanged between the NGINX web server and the client, such as
  session cookies, must have cookie properties set to force the encryption of
  cookies."
  desc  "Cookies can be sent to a client using TLS/SSL to encrypt the cookies,
  but TLS/SSL is not used by every hosted application since the data being
  displayed does not require the encryption of the transmission. To safeguard
  against cookies, especially session cookies, being sent in plaintext, a cookie
  can be encrypted before transmission. To force a cookie to be encrypted before
  transmission, the cookie Secure property can be set."
  
  desc  "check", "Review the NGINX web server documentation and deployed configuration 
  to verify that cookies are encrypted before transmission.

  If it is determined that the web server is not required to perform session 
  management, this check is Not Applicable. 

  Check for the following: 
    # grep the 'proxy_cookie_path' directive in the location context of the 
    nginx.conf and any separated include configuration file.

  If the 'proxy_cookie_path' directive exists and is not set to 'Secure', 
  this is a finding.
  "
  desc  "fix", "If the 'proxy_cookie_path' directive exists in the NGINX 
  configuration file(s), configure it to include the 'Secure' property. 

  Example:
  proxy_cookie_path / '/; HTTPOnly; Secure';"
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000439-WSR-000155"
  tag "gid": "V-56009"
  tag "rid": "SV-70263r2_rule"
  tag "stig_id": "SRG-APP-000439-WSR-000155"
  tag "fix_id": "F-60887r1_fix"
  tag "cci": ["CCI-002418"]
  tag "nist": ["SC-8", "Rev_4"]

  nginx_conf_handle = nginx_conf(input('conf_path'))

  describe nginx_conf_handle do
    its ('params') { should_not be_empty }
  end

  nginx_conf_handle.locations.each do |location|
    values = []
    values.push(location.params['proxy_cookie_path'])
    describe "The 'proxy_cookie_path'" do
      it 'should be configured to HTTPOnly and Secure' do
        expect(values.to_s).to(include "/; HTTPOnly; Secure") 
      end unless location.params['proxy_cookie_path'].nil?
    end
  end
end

