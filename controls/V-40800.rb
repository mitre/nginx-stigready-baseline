# encoding: UTF-8

control "V-40800" do
  title "The NGINX web server must use encryption strength in accordance with the
  categorization of data hosted by the web server when remote connections are
  provided."
  desc  "The NGINX web server has several remote communications channels. Examples
  are user requests via http/https, communication to a backend database, or
  communication to authenticate users. The encryption used to communicate must
  match the data that is being retrieved or presented.

    Methods of communication are http for publicly displayed information, https
  to encrypt when user data is being transmitted, VPN tunneling, or other
  encryption methods to a database.
  "
  desc  "check", "Review the NGINX web server documentation and configuration to determine the 
  communication methods that are being used.

  If NGINX is not configured to serve files, this check is Not Applicable. 

  Check for the following:
  
    # grep the 'ssl_prefer_server_cipher' directive in each server context of the 
    nginx.conf and any separated include configuration file.
  
  Verify that the 'ssl_prefer_server_cipher' directive is set to 'on'. 
  
  If the directive is not set to 'on', this is a finding.
  
    # grep the 'ssl_ciphers' directive in each server context of the nginx.conf and 
    any separated include configuration file.
  
  Verify the encryption being used is in accordance with the categorization of data 
  being hosted when remote connections are provided.
  
  If it is not, then this is a finding.

  If the 'ssl_prefer_server_cipher' and 'ssl_ciphers' directives cannot be found in 
  NGINX configuration files, this check is Not Applicable.
  "
  desc  "fix", "Include the 'ssl_prefer_server_cipher' directive in all server context 
  of the NGINX configuration file(s) and set the directive to 'on'.  
  Configure the nginx web server to use encryption strength equal to the categorization 
  of data hosted when remote connections are provided."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000014-WSR-000006"
  tag "gid": "V-40800"
  tag "rid": "SV-53037r3_rule"
  tag "stig_id": "SRG-APP-000014-WSR-000006"
  tag "fix_id": "F-45963r2_fix"
  tag "cci": ["CCI-000068"]
  tag "nist": ["AC-17 (2)", "Rev_4"]
  
  if nginx_conf.servers.nil?
    impact 0.0
    describe 'This check is NA because NGINX has not been configured to serve files.' do
      skip 'This check is NA because NGINX has not been configured to serve files.'
    end
  else
    nginx_conf.servers.each do |server|
      if server.params["ssl_prefer_server_ciphers"].nil?
        impact 0.0
        describe 'This test is NA because the ssl_prefer_server_ciphers directive has not been configured.' do
          skip 'This test is NA because the ssl_prefer_server_ciphers directive has not been configured.'
        end
      else
        server.params["ssl_prefer_server_ciphers"].each do |prefer_ciphers|
          describe 'The ssl_prefer_server_cipher' do
            it 'should be set to on.' do
              expect(prefer_ciphers).to(cmp 'on')
            end
          end
        end
      end
      if server.params["ssl_ciphers"].nil?
        impact 0.0
        describe 'This test is NA because the ssl_ciphers directive has not been configured.' do
          skip 'This test is NA because the ssl_ciphers directive has not been configured.'
        end
      else
        ciphers_found = []
        server.params["ssl_ciphers"].each do |ciphers|
          ciphers[0].to_s.split("\:").each do |cipher|
            ciphers_found << cipher
          end
        end
        ciphers_found.uniq!
        ciphers_found.each do |cipher|
          describe 'Each cipher' do
            it 'found in configuration should be included in the list of ciphers approved to encrypt data' do
              expect(cipher).to(be_in input('approved_ssl_ciphers'))
            end
          end
        end
      end
    end
  end
end 


