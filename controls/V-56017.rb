# encoding: UTF-8

control "V-56017" do
  title "The NGINX web server must implement required cryptographic protections using
  cryptographic modules complying with applicable federal laws, Executive Orders,
  directives, policies, regulations, standards, and guidance when encrypting data
  that must be compartmentalized."
  desc  "Cryptography is only as strong as the encryption modules/algorithms
  employed to encrypt the data.

    Use of weak or untested encryption algorithms undermines the purposes of
  utilizing encryption to protect data.

    NSA has developed Type 1 algorithms for protecting classified information.
  The Committee on National Security Systems (CNSS) National Information
  Assurance Glossary (CNSS Instruction No. 4009) defines Type 1 products as:

    \"Cryptographic equipment, assembly or component classified or certified by
  NSA for encrypting and decrypting classified and sensitive national security
  information when appropriately keyed. Developed using established NSA business
  processes and containing NSA-approved algorithms are used to protect systems
  requiring the most stringent protection mechanisms.\"

    Although persons may have a security clearance, they may not have a
  \"need-to-know\" and are required to be separated from the information in
  question. The web server must employ NSA-approved cryptography to protect
  classified information from those individuals who have no \"need-to-know\" or
  when encryption of compartmentalized data is required by data classification.
  "
  
  desc  "check", "Review policy documents to identify data that is compartmentalized 
  (i.e.classified, sensitive, need-to-know, etc.) and requires cryptographic
  protection.

  Review the NGINX web server documentation and deployed configuration to 
  identify the encryption modules utilized to protect the compartmentalized 
  data.

  If NGINX is not configured to serve files or if required directive(s) cannot be found in 
  NGINX configuration files, this check is Not Applicable.

  Check for the followng:
    # grep the 'ssl_prefer_server_cipher' directive in each server context of 
    the nginx.conf and any separated include configuration file.

  Verify that the 'ssl_prefer_server_cipher' is set to 'on'. 
  If the directive is not set to 'on', this is a finding.

    # grep the 'ssl_ciphers' directive in each server context of the nginx.conf 
    and any separated include configuration file.

  If the 'ssl_ciphers' directive is configured to include any ciphers that are 
  not compliant with the data, this is a finding. 
  "
  desc  "fix", "Include the 'ssl_prefer_server_cipher' directive in all server 
  context of the NGINX configuration file(s) and set the directive to 'on'.  
  The 'ssl_ciphers' directive should include the required ciphers to protect the 
  compartmentalized data."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000416-WSR-000118"
  tag "gid": "V-56017"
  tag "rid": "SV-70271r2_rule"
  tag "stig_id": "SRG-APP-000416-WSR-000118"
  tag "fix_id": "F-60895r1_fix"
  tag "cci": ["CCI-002450"]
  tag "nist": ["SC-13", "Rev_4"]

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

