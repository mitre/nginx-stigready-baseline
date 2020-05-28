# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-56001" do
  title "The web server must employ cryptographic mechanisms (TLS/DTLS/SSL)
preventing the unauthorized disclosure of information during transmission."
  desc  "Preventing the disclosure of transmitted information requires that the
web server take measures to employ some form of cryptographic mechanism in
order to protect the information during transmission. This is usually achieved
through the use of Transport Layer Security (TLS).

    Transmission of data can take place between the web server and a large
number of devices/applications external to the web server. Examples are a web
client used by a user, a backend database, an audit server, or other web
servers in a web cluster.

    If data is transmitted unencrypted, the data then becomes vulnerable to
disclosure. The disclosure may reveal user identifier/password combinations,
website code revealing business logic, or other user personal information.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployed configuration to determine
whether the transmission of data between the web server and external devices is
encrypted.

    If the web server does not encrypt the transmission, this is a finding.
  "
  desc  "fix", "Configure the web server to encrypt the transmission of data
between the web server and external devices."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000439-WSR-000151"
  tag "gid": "V-56001"
  tag "rid": "SV-70255r2_rule"
  tag "stig_id": "SRG-APP-000439-WSR-000151"
  tag "fix_id": "F-60879r1_fix"
  tag "cci": ["CCI-002418"]
  tag "nist": ["SC-8", "Rev_4"]

  # listen - Context:	server
  Array(nginx_conf(conf_path).servers).each do |server| # solid gold
    describe 'server context:' do
      it 'There should be a listen directive.' do
        expect(server.params).to(include "listen")
      end
      Array(server.params["listen"]).each do |listen|
        it 'The port (' + listen[0].to_s + ') should match this regex: [0-9]{2,4}' do
          expect(listen[0].to_s).to(match /[0-9]{2,4}/)
        end
        it 'It should include ssl.' do
          expect(listen[1].to_s).to(match /ssl/)
        end
      end
    end
  end
end

