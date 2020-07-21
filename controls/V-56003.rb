# encoding: UTF-8

approved_ssl_protocols = input('approved_ssl_protocols')

control "V-56003" do
  title "NGINX web server session IDs must be sent to the client using SSL/TLS."
  desc  "The HTTP protocol is a stateless protocol. To maintain a session, a
session identifier is used. The session identifier is a piece of data that is
used to identify a session and a user. If the session identifier is compromised
by an attacker, the session can be hijacked. By encrypting the session
identifier, the identifier becomes more difficult for an attacker to hijack,
decrypt, and use before the session has expired."
  
  desc  "check", "Review the NGINX web server documentation and deployed 
  configuration to determine whether the session identifier is being sent to 
  he client encrypted.

  If it is determined that the web server is not required to perform session 
  management, this check is Not Applicable. 

  Check if SSL is enabled on the server:
    #grep the 'listen' directive in the server context of the nginx.conf and 
    any separated include configuration file.

  If the 'listen' directive is not configured to use ssl, this is a finding.

  Check for if 'ssl_protocols' is configured:
    #grep the 'ssl_protocols' directive in the server context of the nginx.conf 
    and any separated include configuration file.

  If the 'ssl_protocols' directive does not exist in the configuration or is not 
  set to the approved TLS version, this is a finding. 
  "
  desc  "fix", "Configure the 'listen' directive to the NGINX configuration 
  file(s) to enable the use of SSL to ensure the session IDs are encrypted.

  Add the 'ssl_protocols' directive to the NGINX configuration file(s) and 
  configure it to use the approved TLS protocols to ensure the session IDs 
  are encrypted.
  
  Example:
    server {
            listen 443 ssl;
            ssl_protocols TLSv1.2;
    }"
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000439-WSR-000152"
  tag "gid": "V-56003"
  tag "rid": "SV-70257r2_rule"
  tag "stig_id": "SRG-APP-000439-WSR-000152"
  tag "fix_id": "F-60881r1_fix"
  tag "cci": ["CCI-002418"]
  tag "nist": ["SC-8", "Rev_4"]

  nginx_conf.servers.each do |server|
    describe 'The listen directive' do
      it 'should be included in the configuration.' do
        expect(server.params).to(include "listen")
      end
      if server.params["listen"].nil?
        describe 'Test skipped because the listen directive does not exist.' do
          skip 'This test is skipped since the listen directive does not exist.'
        end
      else
        it 'should be configured with SSL enabled.' do
          expect(server.params["listen"].to_s).to(include "ssl")
        end
      end
    end

    describe 'The ssl_protocols directive' do
      it 'should be included in the configuration.' do
        expect(server.params).to(include "ssl_protocols")
      end
    end
    if server.params["ssl_protocols"].nil?
      describe 'Test skipped because the ssl_protocols directive does not exist.' do
        skip 'This test is skipped since the ssl_protocols directive does not exist.'
      end
    else
      server.params["ssl_protocols"].each do |protocol|
        describe 'Each protocol' do
          it 'should be included in the list of protocols approved to encrypt data' do
            expect(protocol).to(be_in input('approved_ssl_protocols'))
          end
        end
      end
    end 
  end

  if nginx_conf.servers.empty?
    describe 'Test skipped because the server context does not exist.' do
      skip 'This test is skipped since the server context was not found.'
    end
  end 

end

