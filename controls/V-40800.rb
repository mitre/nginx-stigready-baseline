# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-40800" do
  title "The web server must use encryption strength in accordance with the
categorization of data hosted by the web server when remote connections are
provided."
  desc  "The web server has several remote communications channels. Examples
are user requests via http/https, communication to a backend database, or
communication to authenticate users. The encryption used to communicate must
match the data that is being retrieved or presented.

    Methods of communication are http for publicly displayed information, https
to encrypt when user data is being transmitted, VPN tunneling, or other
encryption methods to a database.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and configuration to determine the
communication methods that are being used.

    Verify the encryption being used is in accordance with the categorization
of data being hosted when remote connections are provided.

    If it is not, then this is a finding.
  "
  desc  "fix", "Configure the web server to use encryption strength equal to
the categorization of data hosted when remote connections are provided."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000014-WSR-000006"
  tag "gid": "V-40800"
  tag "rid": "SV-53037r3_rule"
  tag "stig_id": "SRG-APP-000014-WSR-000006"
  tag "fix_id": "F-45963r2_fix"
  tag "cci": ["CCI-000068"]
  tag "nist": ["AC-17 (2)", "Rev_4"]

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
      # This required list may need to be updated based on input from the security team
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

