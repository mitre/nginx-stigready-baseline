# encoding: UTF-8
conf_path = input('conf_path')
authorized_ports = input('authorized_ports')

control "V-55991" do
  title "The NGINX web server must prohibit or restrict the use of nonsecure or
unnecessary ports, protocols, modules, and/or services."
  desc  "Web servers provide numerous processes, features, and functionalities
that utilize TCP/IP ports. Some of these processes may be deemed unnecessary or
too unsecure to run on a production system.

    The web server must provide the capability to disable or deactivate
network-related services that are deemed to be non-essential to the server
mission, are too unsecure, or are prohibited by the PPSM CAL and vulnerability
assessments.
  "
  desc  "rationale", ""
  desc  "check", "
  Review the NGINX web server documentation and deployment configuration to
  determine which ports and protocols are enabled.

  Verify that the ports and protocols being used are permitted, necessary for
  the operation of the web server and the hosted applications and are secure for
  a production system.

  Check for the following:
  # grep for all 'listen' directives in the server context of the nginx.conf and 
  any separated include configuration file.

  If the 'listen' directive is not configured to use port 80 (for HTTP) or port 
  443 (for HTTPS) and port configured is not approved for used by PPSM, this is 
  a finding.
  "
  desc  "fix", "Configure the 'listen' directives in the NGINX configuration file(s) 
  to use IANA well-known ports for 'HTTP' and 'HTTPS'."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000383-WSR-000175"
  tag "gid": "V-55991"
  tag "rid": "SV-70245r2_rule"
  tag "stig_id": "SRG-APP-000383-WSR-000175"
  tag "fix_id": "F-60869r1_fix"
  tag "cci": ["CCI-001762"]
  tag "nist": ["CM-7 (1) (b)", "Rev_4"]

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

