# encoding: UTF-8

control "V-41730" do
  title "The NGINX web server must perform RFC 5280-compliant certification path
  validation."
  desc  "A certificate's certification path is the path from the end entity
  certificate to a trusted root certification authority (CA). Certification path
  validation is necessary for a relying party to make an informed decision
  regarding acceptance of an end entity certificate. Certification path
  validation includes checks such as certificate issuer trust, time validity and
  revocation status for each certificate in the certification path. Revocation
  status information for CA and subject certificates in a certification path is
  commonly provided via certificate revocation lists (CRLs) or online certificate
  status protocol (OCSP) responses."
  
  desc  "check", "Review the NGINX web server documentation and deployed configuration 
  to determine whether the web server provides PKI functionality that validates certification
  paths in accordance with RFC 5280.

  If PKI is not being used, this is check is Not Applicable.

  Check for the following:
    # grep the 'ssl_verify_client' and 'ssl_verify_depth' directives in the server 
    context of the nginx.conf and any separated include configuration file.

  If the 'ssl_verify_client' directive does not exist or is not set to 'on', 
  this is a finding. 

  A 'ssl_very_depth' setting of '0' would allow self-signed CAs to validate client 
  certificates. If 'ssl_verify_depth' does not exist or is set to '0', this is a finding.
  "
  desc  "fix", "Ensure that client verification is enabled. For each enabled hosted application 
  on the server, enable and set 'ssl_verify_client' to 'on' and and ensure that the server is 
  configured to verify the client certificate by enabling 'ssl_verify_depth'.

  Example:
  
  ssl_verify_client on;
  ssl_verify_depth 1;  "

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000175-WSR-000095"
  tag "gid": "V-41730"
  tag "rid": "SV-54307r3_rule"
  tag "stig_id": "SRG-APP-000175-WSR-000095"
  tag "fix_id": "F-47189r4_fix"
  tag "cci": ["CCI-000185"]
  tag "nist": ["IA-5 (2) (a)", "Rev_4"]

  nginx_conf_handle = nginx_conf(input('conf_path'))

  describe nginx_conf_handle do
    its ('params') { should_not be_empty }
  end

  nginx_conf_handle.servers.each do |server|
    describe 'The directive' do
      it 'ssl_verify_client should exist in the server context.' do
        expect(server.params).to(include "ssl_verify_client")
      end 
      it 'ssl_verify_depth should exist in the server context.' do
        expect(server.params).to(include "ssl_verify_depth")
      end 
      server.params["ssl_verify_client"].each do |ssl_verify_client|
        it "ssl_verify_client should be set to 'on'." do
          expect(ssl_verify_client).to(cmp 'on')
        end
      end unless server.params["ssl_verify_client"].nil?
      server.params["ssl_verify_depth"].each do |ssl_verify_client|
        it "ssl_verify_depth should not equal '0'." do
          expect(ssl_verify_client).not_to(cmp '0')
        end
      end unless server.params["ssl_verify_depth"].nil?
    end
  end 
end