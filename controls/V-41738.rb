# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-41738" do
  title "The web server must encrypt passwords during transmission."
  desc  "Data used to authenticate, especially passwords, needs to be protected
at all times, and encryption is the standard method for protecting
authentication data during transmission. Data used to authenticate can be
passed to and from the web server for many reasons.

    Examples include data passed from a user to the web server through an HTTPS
connection for authentication, the web server authenticating to a backend
database for data retrieval and posting, and the web server authenticating to a
clustered web server manager for an update.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployed configuration to determine
whether passwords are being passed to or from the web server.

    If the transmission of passwords is not encrypted, this is a finding.
  "
  desc  "fix", "Configure the web server to encrypt the transmission passwords."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000172-WSR-000104"
  tag "gid": "V-41738"
  tag "rid": "SV-54315r3_rule"
  tag "stig_id": "SRG-APP-000172-WSR-000104"
  tag "fix_id": "F-47197r2_fix"
  tag "cci": ["CCI-000197"]
  tag "nist": ["IA-5 (1) (c)", "Rev_4"]

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

