# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-41706" do
  title "The web server must be configured to use a specified IP address and
port."
  desc  "The web server must be configured to listen on a specified IP address
and port.  Without specifying an IP address and port for the web server to
utilize, the web server will listen on all IP addresses available to the
hosting server.  If the web server has multiple IP addresses, i.e., a
management IP address, the web server will also accept connections on the
management IP address.

    Accessing the hosted application through an IP address normally used for
non-application functions opens the possibility of user access to resources,
utilities, files, ports, and protocols that are protected on the desired
application IP address.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployment configuration to
determine whether the web server is configured to listen on a specified IP
address and port.

    Request a client user try to access the web server on any other available
IP addresses on the hosting hardware.

    If an IP address is not configured on the web server or a client can reach
the web server on other IP addresses assigned to the hosting hardware, this is
a finding.
  "
  desc  "fix", "Configure the web server to only listen on a specified IP
address and port."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000142-WSR-000089"
  tag "gid": "V-41706"
  tag "rid": "SV-54283r3_rule"
  tag "stig_id": "SRG-APP-000142-WSR-000089"
  tag "fix_id": "F-47165r2_fix"
  tag "cci": ["CCI-000382"]
  tag "nist": ["CM-7 b", "Rev_4"]

  # Review the results for the followingdirective: listen
  # For any enabled Listen directives ensure they specify both an IP address and
  # port number.
  # If the Listen directive is found with only an IP address, or only a port
  # number specified, this is finding. If the IP address is all zeros (i.e.
  # 0.0.0.0:80 or [::ffff:0.0.0.0]:80, this is a finding. If the Listen
  # directive does not exist, this is a finding.

  nginx_conf(conf_path).servers.entries.each do |server|
    server.params['listen'].each do |listen|
      describe listen.join do
        it { should match %r([0-9]+(?:\.[0-9]+){3}|[a-zA-Z]:[0-9]+) }
      end
      describe listen.join.split(':').first do
        it { should_not cmp '0.0.0.0' }
        it { should_not cmp '[::ffff:0.0.0.0]' }
      end
    end unless server.params['listen'].nil?
  end
end

