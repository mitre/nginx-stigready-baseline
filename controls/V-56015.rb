# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-56015" do
  title "The web server must maintain the confidentiality and integrity of
information during reception."
  desc  "Information can be either unintentionally or maliciously disclosed or
modified during reception, including, for example, during aggregation, at
protocol transformation points, and during packing/unpacking. These
unauthorized disclosures or modifications compromise the confidentiality or
integrity of the information.

    Protecting the confidentiality and integrity of received information
requires that application servers take measures to employ approved cryptography
in order to protect the information during transmission over the network. This
is usually achieved through the use of Transport Layer Security (TLS), SSL VPN,
or IPsec tunnel.

    The web server must utilize approved encryption when receiving transmitted
data.
  "
  desc  "rationale", ""
  desc  "check", "
    Review web server configuration to determine if the server is using a
transmission method that maintains the confidentiality and integrity of
information during reception.

    If a transmission method is not being used that maintains the
confidentiality and integrity of the data during reception, this is a finding.
  "
  desc  "fix", "Configure the web server to utilize a transmission method that
maintains the confidentiality and integrity of information during reception."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000442-WSR-000182  "
  tag "gid": "V-56015"
  tag "rid": "SV-70269r2_rule"
  tag "stig_id": "SRG-APP-000442-WSR-000182"
  tag "fix_id": "F-60893r1_fix"
  tag "cci": ["CCI-002422"]
  tag "nist": ["SC-8 (2)", "Rev_4"]

  fips_compliant_protocols= input(
    'fips_compliant_protocols',
    description: 'List of protocols that are FIPS compliant',
    value: [
              "TLSv1.1",
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

