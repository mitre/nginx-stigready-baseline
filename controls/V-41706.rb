# encoding: UTF-8

control "V-41706" do
  title "The NGINX web server must be configured to use a specified IP address and
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
  
  desc  "check", "Review the NGINX web server documentation and deployment
  configuration to determine whether the web server is configured to listen 
  on a specified IP address and port.

  If NGINX is not configured to serve files or if required directive(s) cannot 
  be found in NGINX configuration files, this check is Not Applicable.

  Check for the following:
    # grep the 'listen' directive in the server context of the nginx.conf and any separated include configuration file.

  Verify that any enabled 'listen' directives specify both an IP address and port number.

  If the 'listen' directive is found with only an IP address or only a port number specified, this is finding.

  If the IP address is all zeros (i.e., 0.0.0.0:80 or [::ffff:0.0.0.0]:80), this is a finding.
  "
  desc  "fix", "Configure the 'listen' directive in the server context of the NGINX configuration file(s) to listen on a 
  specific IP address and port."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000142-WSR-000089"
  tag "gid": "V-41706"
  tag "rid": "SV-54283r3_rule"
  tag "stig_id": "SRG-APP-000142-WSR-000089"
  tag "fix_id": "F-47165r2_fix"
  tag "cci": ["CCI-000382"]
  tag "nist": ["CM-7 b", "Rev_4"]

  if nginx_conf.servers.nil?
    impact 0.0
    describe 'This check is NA because NGINX has not been configured to serve files.' do
      skip 'This check is NA because NGINX has not been configured to serve files.'
    end
  else
    nginx_conf.servers.each do |server|
      describe 'The listen directive' do
        if server.params["listen"].nil?
          impact 0.0
          describe 'This test is NA because the listen directive has not been configured.' do
            skip 'This test is NA because the listen directive has not been configured.'
          end
        else 
          server.params["listen"].each do |listen|
            it 'should include both the IP and port number.' do
              expect(listen.join).to(match %r([0-9]+(?:\.[0-9]+){3}|[a-zA-Z]:[0-9]+) )
            end
            it 'should not be 0.0.0.0:80 or [::ffff:0.0.0.0]:80.' do
              expect(listen.join.split(':').first).not_to(cmp '0.0.0.0')
              expect(listen.join.split(':').first).not_to(cmp '[::ffff:0.0.0.0]')
            end
          end
        end 
      end
    end
  end
end

