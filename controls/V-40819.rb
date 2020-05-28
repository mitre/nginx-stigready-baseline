# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-40819" do
  title "The web server must use cryptography to protect the integrity of
remote sessions."
  desc  "Data exchanged between the user and the web server can range from
static display data to credentials used to log into the hosted application.
Even when data appears to be static, the non-displayed logic in a web page may
expose business logic or trusted system relationships. The integrity of all the
data being exchanged between the user and web server must always be trusted. To
protect the integrity and trust, encryption methods should be used to protect
the complete communication session."
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and configuration to make certain that
the web server is configured to use cryptography to protect the integrity of
remote access sessions.

    If the web server is not configured to use cryptography to protect the
integrity of remote access sessions, this is a finding.
  "
  desc  "fix", "Configure the web server to utilize encryption during remote
access sessions."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000015-WSR-000014"
  tag "gid": "V-40819"
  tag "rid": "SV-53068r3_rule"
  tag "stig_id": "SRG-APP-000015-WSR-000014"
  tag "fix_id": "F-45994r2_fix"
  tag "cci": ["CCI-001453"]
  tag "nist": ["AC-17 (2)", "Rev_4"]

  required_ssl_protocols= input(
    'ssl_protocols',
    description: 'List of protocols required',
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
        it 'should be included in the list of protocols required to encrypt data' do
          expect(protocols).to(be_in required_ssl_protocols)
        end
      end
    end
  end
end

