# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-61353" do
  title "The web server must remove all export ciphers to protect the
confidentiality and integrity of transmitted information."
  desc  "During the initial setup of a Transport Layer Security (TLS)
connection to the web server, the client sends a list of supported cipher
suites in order of preference.  The web server will reply with the cipher suite
it will use for communication from the client list.  If an attacker can
intercept the submission of cipher suites to the web server and place, as the
preferred cipher suite, a weak export suite, the encryption used for the
session becomes easy for the attacker to break, often within minutes to hours."
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployed configuration to determine
if export ciphers are removed.

    If the web server does not have the export ciphers removed, this is a
finding.

  "
  desc  "fix", "Configure the web server to have export ciphers removed."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000439-WSR-000188 "
  tag "gid": "V-61353"
  tag "rid": "SV-75835r1_rule"
  tag "stig_id": "SRG-APP-000439-WSR-000188"
  tag "fix_id": "F-67255r1_fix"
  tag "cci": ["CCI-002418"]
  tag "nist": ["SC-8", "Rev_4"]

  # ssl_prefer_server_ciphers - Context:	http, server
  Array(nginx_conf(conf_path).servers).each do |server|
    describe 'Each server context' do
      it 'should include the ssl_prefer_server_ciphers directive.' do
        expect(server.params).to(include "ssl_prefer_server_ciphers")
      end
    end
    Array(server.params["ssl_prefer_server_ciphers"]).each do |prefer_ciphers|
      describe 'The ssl_prefer_server_cipher' do
        it 'should be set to on.' do
          expect(prefer_ciphers).to(cmp 'on')
        end
      end
      # Test to see if there is an exact match of ciphers.
      # Create an array with all of the ciphers found in the server section of the config file.
      found = []
      Array(server.params["ssl_ciphers"]).each do |ciphers|
        ciphers[0].to_s.split("\:").each do |cipher|
          # puts "Found this cipher: " + cipher
          found << cipher
        end
      end
      # Create an array with the set of required protocol.
      # NOTE: Some sites show +'s in the cipher names, while others use -'s.  
      # Not sure which is right.
      required = ["ECDH-AESGCM", "DH-AESGCM", "ECDH-AES256", "DH-AES256", "ECDH-AES128", "DH-AES", "ECDH-3DES", "DH-3DES", "RSA-AESGCM", "RSA-AES", "RSA-3DES", "!aNULL", "!eNULL", "!EXPORT", "!DES", "!PSK", "!RC4", "!MD5"]
      # Remove all duplicates
      found.uniq
      required.uniq
      # Compare to make sure the arrays are identical.
      describe 'The exact number of expected ciphers (' + required.size.to_s + ')' do
        it 'should exist.' do
          expect(found.size==required.size).to(cmp true)
        end
      end
      describe 'The correct set of ciphers' do
        it 'should be found.' do
          expect(found & required == required).to(cmp true)
        end
      end
    end
  end
end

