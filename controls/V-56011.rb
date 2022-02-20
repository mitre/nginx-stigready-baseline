control 'V-56011' do
  title "A web server must maintain the confidentiality of controlled
  information during transmission through the use of an approved TLS version."
  desc  "Transport Layer Security (TLS) is a required transmission protocol for
  a web server hosting controlled information. The use of TLS provides
  confidentiality of data in transit between the web server and client. FIPS
  140-2 approved TLS versions must be enabled and non-FIPS-approved SSL versions
  must be disabled.

  NIST SP 800-52 defines the approved TLS versions for government
  applications.
  "

  desc 'check', "Review the NGINX web server documentation and deployed configuration
  to determine which version of TLS is being used.

  If NGINX is not configured to serve files, this check is Not Applicable.

  Check for the following:
    #grep the 'ssl_protocols' directive in the server context of the nginx.conf and any
    separated include configuration file.

  If the 'ssl_protocols' directive cannot be found in NGINX configuration files,
  this check is Not Applicable.

  If the 'ssl_protocols' directive not set to the approved TLS version, this is a finding.
  "
  desc 'fix', "Add the 'ssl_protocols' directive to the NGINX configuration file(s) and
  configure it to use only the approved TLS protocols.

  Example:
    server {
            ssl_protocols TLSv1.2;
    }
  "
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000439-WSR-000156'
  tag "gid": 'V-56011'
  tag "rid": 'SV-70265r2_rule'
  tag "stig_id": 'SRG-APP-000439-WSR-000156'
  tag "fix_id": 'F-60889r1_fix'
  tag "cci": ['CCI-002418']
  tag "nist": %w(SC-8)

  if nginx_conf.servers.nil?
    impact 0.0
    describe 'This check is NA because NGINX has not been configured to serve files.' do
      skip 'This check is NA because NGINX has not been configured to serve files.'
    end
  else
    nginx_conf.servers.each do |server|
      if server.params['ssl_protocols'].nil?
        impact 0.0
        describe 'This test is NA because the ssl_protocols directive has not been configured.' do
          skip 'This test is NA because the ssl_protocols directive has not been configured.'
        end
      else
        server.params['ssl_protocols'].each do |protocol|
          describe 'Each protocol' do
            it 'should be included in the list of protocols approved to encrypt data' do
              expect(protocol).to(be_in(input('approved_ssl_protocols')))
            end
          end
        end
      end
    end
  end
end
