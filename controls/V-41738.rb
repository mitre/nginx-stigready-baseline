# encoding: UTF-8

control "V-41738" do
  title "The NGINX web server must encrypt passwords during transmission."
  desc  "Data used to authenticate, especially passwords, needs to be protected
  at all times, and encryption is the standard method for protecting
  authentication data during transmission. Data used to authenticate can be
  passed to and from the web server for many reasons.

    Examples include data passed from a user to the web server through an HTTPS
  connection for authentication, the web server authenticating to a backend
  database for data retrieval and posting, and the web server authenticating to a
  clustered web server manager for an update.
  "
  
  desc  "check", "Review the NGINX web server documentation and deployed 
  configuration to determine whether passwords are being passed to or from the 
  web server.
  
  If NGINX is not configured to serve files, this check is Not Applicable.

  Check for the following:
    #grep the 'ssl_protocols' directive in the server context of the nginx.conf 
    and any separated include configuration file.

  If the 'ssl_protocols' directive cannot be found in NGINX configuration files, 
  this check is Not Applicable.  

  If TLS is not enabled, then passwords are not encrypted. If the 'ssl_protocols' 
  directive is not set to the approved TLS versions, this is a finding. 
  "
  desc  "fix", "Add the 'ssl_protocols' directive to the NGINX configuration file(s) 
  and configure it to use the approved TLS protocols to encrypt the transmission passwords.
  
  Example:
  server {
          ssl_protocols TLSv1.2;
  }
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000172-WSR-000104"
  tag "gid": "V-41738"
  tag "rid": "SV-54315r3_rule"
  tag "stig_id": "SRG-APP-000172-WSR-000104"
  tag "fix_id": "F-47197r2_fix"
  tag "cci": ["CCI-000197"]
  tag "nist": ["IA-5 (1) (c)", "Rev_4"]

  if nginx_conf.servers.nil?
    impact 0.0
    describe 'This check is NA because NGINX has not been configured to serve files.' do
      skip 'This check is NA because NGINX has not been configured to serve files.'
    end
  else
    nginx_conf.servers.each do |server|
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

