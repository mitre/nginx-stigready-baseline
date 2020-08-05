# encoding: UTF-8

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

  If NGINX is not configured to serve files, this check is Not Applicable.

  Check if SSL is enabled on the server:
    #grep the 'listen' directive in the server context of the nginx.conf and 
    any separated include configuration file.

  If the 'listen' directive is not configured to use ssl, this is a finding.

  Check for if 'ssl_protocols' is configured:
    #grep the 'ssl_protocols' directive in the server context of the nginx.conf 
    and any separated include configuration file.

  If the 'ssl_protocols' directive is not set to the approved TLS version, this is a finding. 

  If the 'listen' and 'ssl_protocols' directives cannot be found in NGINX configuration files, 
  this check is Not Applicable.
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

  if input('performs_session_management') == "false"
    impact 0.0
    describe 'This check is NA because session management is not required.' do
      skip 'This check is NA because session management is not required.'
    end
  else
    if nginx_conf.servers.nil?
      impact 0.0
      describe 'This check is NA because NGINX has not been configured to serve files.' do
        skip 'This check is NA because NGINX has not been configured to serve files.'
      end
    else
      nginx_conf.servers.each do |server|
        describe 'The listen directive' do
          if server.params["listen"].nil?
            impact 0.0
            describe 'This test is NA because the listen directive has not been configured.' do
              skip 'This test is NA because the listen directive has not been configured.'
            end
          else
            it 'should be configured with SSL enabled.' do
              expect(server.params["listen"].to_s).to(include "ssl")
            end
          end
        end
        if server.params["ssl_protocols"].nil?
          impact 0.0
          describe 'This test is NA because the ssl_protocols directive has not been configured.' do
            skip 'This test is NA because the ssl_protocols directive has not been configured.'
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
    end 
  end
end

