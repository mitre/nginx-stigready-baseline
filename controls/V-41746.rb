# encoding: UTF-8

control "V-41746" do
  title "The NGINX web server must use cryptographic modules that meet the
  requirements of applicable federal laws, Executive Orders, directives,
  policies, regulations, standards, and guidance for such authentication."
  desc  "Encryption is only as good as the encryption modules utilized.
  Unapproved cryptographic module algorithms cannot be verified and cannot be
  relied upon to provide confidentiality or integrity, and DoD data may be
  compromised due to weak algorithms.

    FIPS 140-2 is the current standard for validating cryptographic modules and
  NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based
  encryption modules.

    The web server must provide FIPS-compliant encryption modules when
  authenticating users and processes.
  "
  
  desc  "check", "
  Review NGINX web server documentation and deployed configuration to determine
  whether the encryption modules utilized for authentication are FIPS 140-2
  compliant.  Reference the following NIST site to identify validated encryption
  modules: http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-all.htm

  Check for the following:
    #grep the 'ssl_protocols' directive in the server context of the nginx.conf 
    and any separated include configuration file.

  If the 'ssl_protocols' directive does not exist in the configuration or is not 
  set to the FIPS comliant TLS versions, this is a finding. 
  "
  desc  "fix", "Add the 'ssl_protocols' directive to the NGINX configuration file(s) 
  and configure it to use the FIPS compliant TLS protocols.
  Example:
  server {
          ssl_protocols TLSv1.2;
  }
  "

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000179-WSR-000111"
  tag "gid": "V-41746"
  tag "rid": "SV-54323r3_rule"
  tag "stig_id": "SRG-APP-000179-WSR-000111"
  tag "fix_id": "F-47205r2_fix"
  tag "cci": ["CCI-000803"]
  tag "nist": ["IA-7", "Rev_4"]

  if nginx_conf.servers.empty?
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

