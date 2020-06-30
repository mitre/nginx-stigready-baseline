# encoding: UTF-8
conf_path = input('conf_path')
approved_ssl_protocols = input('approved_ssl_protocols')

control "V-40819" do
  title "The NGINX web server must use cryptography to protect the integrity of
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
  Review the NGINX web server documentation and configuration to make certain that the 
  NGINX web server is configured to use cryptography to protect the integrity of remote 
  access sessions.

  Check for the following:
    #grep the 'ssl_protocols' directive in the server context of the nginx.conf 
    and any separated include configuration file.
  
  If the 'ssl_protocols' directive does not exist in the configuration or is not set to 
  the approved TLS version, this is a finding. 
  "
  desc  "fix", "Add the 'ssl_protocols' directive to the NGINX configuration file(s) 
  and configure it to use the approved TLS protocols to utilize encryption during 
  remote access sessions.
  
  Example:
  server {
          ssl_protocols TLSv1.2;
  }
"
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000015-WSR-000014"
  tag "gid": "V-40819"
  tag "rid": "SV-53068r3_rule"
  tag "stig_id": "SRG-APP-000015-WSR-000014"
  tag "fix_id": "F-45994r2_fix"
  tag "cci": ["CCI-001453"]
  tag "nist": ["AC-17 (2)", "Rev_4"]

  nginx_conf_handle = nginx_conf(conf_path)

  describe nginx_conf_handle do
    its ('params') { should_not be_empty }
  end

  Array(nginx_conf_handle.servers).each do |server|
    describe 'Each server context' do
      it 'should include a ssl_protocols directive.' do
        expect(server.params).to(include "ssl_protocols")
      end
    end
    Array(server.params["ssl_protocols"]).each do |protocol|
      describe 'Each protocol' do
        it 'should be included in the list of protocols approved to encrypt data' do
          expect(protocol).to(be_in approved_ssl_protocols)
        end
      end
    end
  end
end

