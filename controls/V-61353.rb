# encoding: UTF-8

control "V-61353" do
  title "The web server must remove all export ciphers to protect the
confidentiality and integrity of transmitted information."
  desc  "During the initial setup of a Transport Layer Security (TLS)
connection to the web server, the client sends a list of supported cipher
suites in order of preference.  The web server will reply with the cipher suite
it will use for communication from the client list.  If an attacker can
intercept the submission of cipher suites to the web server and place, as the
preferred cipher suite, a weak export suite, the encryption used for the
session becomes easy for the attacker to break, often within minutes to hours."
  
  desc  "check", "
  Review the web server documentation and deployed configuration to determine
  if export ciphers are removed.

  If NGINX is not configured to serve files or if required directive(s) cannot be found in 
  NGINX configuration files, this check is Not Applicable.

    Check for the following:

    # grep the 'ssl_prefer_server_cipher' directive in each server context of 
    the nginx.conf and any separated include configuration file.

  Verify that the 'ssl_prefer_server_cipher' directive exists and is set to 'on'. 
  If the directive does not exist or is not set to 'on', this is a finding.

    # grep the 'ssl_ciphers' directive in each server context of the nginx.conf 
    and any separated include configuration file.

  If the 'ssl_ciphers' directive is configured to include any export ciphers, 
  this is a finding. 

  "
  desc  "fix", "Include the 'ssl_prefer_server_cipher' directive in all server 
  context of the NGINX configuration file(s) and set the directive to 'on'.  
  The 'ssl_ciphers' directive should not include any export ciphers. "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000439-WSR-000188 "
  tag "gid": "V-61353"
  tag "rid": "SV-75835r1_rule"
  tag "stig_id": "SRG-APP-000439-WSR-000188"
  tag "fix_id": "F-67255r1_fix"
  tag "cci": ["CCI-002418"]
  tag "nist": ["SC-8", "Rev_4"]

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

