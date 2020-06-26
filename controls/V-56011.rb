# encoding: UTF-8
conf_path = input('conf_path')
approved_ssl_protocols = input('approved_ssl_protocols')

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
  Review the NGINX web server documentation and deployed configuration to determine
  which version of TLS is being used.

  Check for the following:
    #grep the 'ssl_protocols' directive in the server context of the nginx.conf and any separated include configuration file.

  If the 'ssl_protocols' directive does not exist in the configuration or is not set to the approved TLS version, this is a finding. 
  "
  desc  "fix", "Add the 'ssl_protocols' directive to the Nginx configuration file(s) and configure it to use only the approved TLS protocols. 

  Example:
    server {
            ssl_protocols TLSv1.2;
    }
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000439-WSR-000156"
  tag "gid": "V-56011"
  tag "rid": "SV-70265r2_rule"
  tag "stig_id": "SRG-APP-000439-WSR-000156"
  tag "fix_id": "F-60889r1_fix"
  tag "cci": ["CCI-002418"]
  tag "nist": ["SC-8", "Rev_4"]

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

