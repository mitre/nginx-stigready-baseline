# encoding: UTF-8
conf_path = input('conf_path')
key_file_path = input('key_file_path')

sys_admin = input('sys_admin')
sys_admin_group = input('sys_admin_group')

control "V-41731" do
  title "Only authenticated system administrators or the designated PKI Sponsor
for the NGINX web server must have access to the web servers private key."
  desc  "The web server's private key is used to prove the identity of the
server to clients and securely exchange the shared secret key used to encrypt
communications between the web server and clients.

    By gaining access to the private key, an attacker can pretend to be an
authorized server and decrypt the SSL traffic between a client and the web
server.
  "
  desc  "rationale", ""
  desc  "check", "
  If the NGINX web server does not have a private key, this check is Not Applicable.

  Review the web server documentation and deployed configuration to determine
  whether only authenticated system administrators and the designated PKI Sponsor
  for the web server can access the web server private key.

  Check for the following:
    # grep the 'ssl_certificate' and 'ssl_certificate_key' directives in the server 
    context of the nginx.conf and any separated include configuration file.
  
    #   ls -l on these files to determine ownership of the file
   
     -The SA or Designated PKI Sponsor should be the owner of the web server private key
     - Permissions on these files should be 400
  
  If the private key is accessible by unauthenticated or unauthorized users, this is a finding.
  "
  desc  "fix", "Configure the Nginx web server to ensure only authenticated and authorized 
  users can access the web server's private key.

  Run the following commands:
   
    # cd <'private key path'>/
    # chown <'authorized user'>:<'authorized group'> <'private key file'>
    # chmod 400  <'private key file'>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000176-WSR-000096"
  tag "gid": "V-41731"
  tag "rid": "SV-54308r3_rule"
  tag "stig_id": "SRG-APP-000176-WSR-000096"
  tag "fix_id": "F-47190r2_fix"
  tag "cci": ["CCI-000186"]
  tag "nist": ["IA-5 (2) (b)", "Rev_4"]


  nginx_conf_handle = nginx_conf(conf_path)

  describe nginx_conf_handle do
    its ('params') { should_not be_empty }
  end

  Array(nginx_conf_handle.servers).each do |server|
    describe 'The directive' do
      it 'ssl_certificate should exist in the server context.' do
        expect(server.params).to(include "ssl_certificate")
      end
      it 'ssl_certificate_key should exist in the server context.' do
        expect(server.params).to(include "ssl_certificate_key")
      end  
    end
    describe 'The private key should have the following permissions:' do
      Array(server.params["ssl_certificate"]).each do |certificate|
        certificate_string = certificate.to_s
        describe file(certificate.join) do
          its('owner') { should be_in sys_admin_group }
          its('group') { should be_in sys_admin_group }
          its('mode') { should cmp '0400' }
        end
      end
      Array(server.params["ssl_certificate_key"]).each do |certificate_key|
        describe file(certificate_key.join) do
          its('owner') { should be_in sys_admin_group }
          its('group') { should be_in sys_admin_group }
          its('mode') { should cmp '0400' }
        end
      end
    end
  end 
end


