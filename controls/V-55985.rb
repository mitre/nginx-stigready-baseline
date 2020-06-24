# encoding: UTF-8
conf_path = input('conf_path')
authorized_ports = input('authorized_ports')

control "V-55985" do
  title "The NGINX web server must be configured in accordance with the security
configuration settings based on DoD security configuration or implementation
guidance, including STIGs, NSA configuration guides, CTOs, and DTMs."
  desc  "Configuring the web server to implement organization-wide security
implementation guides and security checklists guarantees compliance with
federal standards and establishes a common security baseline across the DoD
that reflects the most restrictive security posture consistent with operational
requirements.

    Configuration settings are the set of parameters that can be changed that
affect the security posture and/or functionality of the system.
Security-related parameters are those parameters impacting the security state
of the web server, including the parameters required to satisfy other security
control requirements.
  "
  desc  "rationale", ""
  desc  "check", "
  Review the NGINX web server documentation and deployed configuration to determine
  if web server is configured in accordance with the security configuration
  settings based on DoD security configuration or implementation guidance.

  Review the website to determine if 'HTTP' and 'HTTPS' are used in accordance 
  with well-known ports (e.g., 80 and 443) or those ports and services as registered 
  and approved for use by the DoD Ports, Protocols, and Services Management (PPSM).

  Verify that any variation in PPS is documented, registered, and approved by the PPSM.

  Check for the following:
    # grep for all 'listen' directives in the server context of the nginx.conf and 
    any separated include configuration file.

  If the 'listen' directive is not configured to use port 80 (for HTTP) or port 
  443 (for HTTPS) and port configured is not approved for used by PPSM, this is 
  a finding.
  "
  desc  "fix", "Configure the 'listen' directives in the Nginx configuration file(s) 
  to use IANA well-known ports for 'HTTP' and 'HTTPS'."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000516-WSR-000174"
  tag "gid": "V-55985"
  tag "rid": "SV-70239r2_rule"
  tag "stig_id": "SRG-APP-000516-WSR-000174"
  tag "fix_id": "F-60863r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]

  nginx_conf_handle = nginx_conf(conf_path)

  describe nginx_conf_handle do
    its ('params') { should_not be_empty }
  end
  
  nginx_conf(conf_path).servers.entries.each do |server|
    server.params['listen'].each do |listen|
      describe "The listen directive" do
        listen_address = listen.join
        it "should include the specific IP address and port" do
          expect(listen_address).to(match %r([0-9]+(?:\.[0-9]+){3}|[a-zA-Z]:[0-9]+) )
        end 
      end
      describe "The listening port" do
        listen_port = listen.join.split(':')[1]
        it "should be an approved port." do
          expect(listen_port).to(be_in authorized_ports)
        end 
      end
    end unless server.params['listen'].nil?
  end 
end

