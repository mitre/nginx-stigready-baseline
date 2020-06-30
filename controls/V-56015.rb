# encoding: UTF-8
conf_path = input('conf_path')
approved_ssl_protocols = input('approved_ssl_protocols')

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

  Check for the following:
    #grep the 'ssl_protocols' directive in the server context of the nginx.conf 
    and any separated include configuration file.

  If the 'ssl_protocols' directive does not exist in the configuration or is not 
  set to the approved TLS version, this is a finding. 
  "
  desc  "fix", "Add the 'ssl_protocols' directive to the NGINX configuration 
  file(s) and configure it to use only the approved TLS protocols to maintain 
  the confidentiality and integrity of information during reception.

  Example:
    server {
            ssl_protocols TLSv1.2;
    }"
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000442-WSR-000182  "
  tag "gid": "V-56015"
  tag "rid": "SV-70269r2_rule"
  tag "stig_id": "SRG-APP-000442-WSR-000182"
  tag "fix_id": "F-60893r1_fix"
  tag "cci": ["CCI-002422"]
  tag "nist": ["SC-8 (2)", "Rev_4"]

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

