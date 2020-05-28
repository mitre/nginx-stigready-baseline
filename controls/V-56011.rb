# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-56011" do
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
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployed configuration to determine
which version of TLS is being used.

    If the TLS version is not an approved version according to NIST SP 800-52
or non-FIPS-approved algorithms are enabled, this is a finding.
  "
  desc  "fix", "Configure the web server to use an approved TLS version
according to NIST SP 800-52 and to disable all non-approved versions."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000439-WSR-000156"
  tag "gid": "V-56011"
  tag "rid": "SV-70265r2_rule"
  tag "stig_id": "SRG-APP-000439-WSR-000156"
  tag "fix_id": "F-60889r1_fix"
  tag "cci": ["CCI-002418"]
  tag "nist": ["SC-8", "Rev_4"]

  fips_compliant_protocols= input(
    'fips_compliant_protocols',
    description: 'List of protocols that are FIPS compliant',
    value: [
              "TLSv1.2"
            ]
  )

  Array(nginx_conf(conf_path).servers).each do |server|
    describe 'Each server context' do
      it 'should include a ssl_protocols directive.' do
        expect(server.params).to(include "ssl_protocols")
      end
    end
    Array(server.params["ssl_protocols"]).each do |protocols|
      describe 'Each protocol' do
        it 'should be included in the list of protocols that are FIPS compliant.' do
          expect(protocols).to(be_in fips_compliant_protocols)
        end
      end
    end
  end 
end

