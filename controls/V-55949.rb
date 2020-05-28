# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-55949" do
  title "The web server must set an inactive timeout for sessions."
  desc  "Leaving sessions open indefinitely is a major security risk. An
attacker can easily use an already authenticated session to access the hosted
application as the previously authenticated user. By closing sessions after a
set period of inactivity, the web server can make certain that those sessions
that are not closed through the user logging out of an application are
eventually closed.

    Acceptable values are 5 minutes for high-value applications, 10 minutes for
medium-value applications, and 20 minutes for low-value applications.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the hosted applications, web server documentation and deployed
configuration to verify that the web server will close an open session after a
configurable time of inactivity.

    If the web server does not close sessions after a configurable time of
inactivity or the amount of time is configured higher than 5 minutes for
high-risk applications, 10 minutes for medium-risk applications, or 20 minutes
for low-risk applications, this is a finding.
  "
  desc  "fix", "Configure the web server to close inactive sessions after 5
minutes for high-risk applications, 10 minutes for medium-risk applications, or
20 minutes for low-risk applications."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000295-WSR-000134"
  tag "gid": "V-55949"
  tag "rid": "SV-70203r2_rule"
  tag "stig_id": "SRG-APP-000295-WSR-000134"
  tag "fix_id": "F-60827r1_fix"
  tag "cci": ["CCI-002361"]
  tag "nist": ["AC-12", "Rev_4"]

  Array(nginx_conf(conf_path).params['http']).each do |http|
    # Within http
    describe 'The http context keep-alive value' do
      it 'should be from 10 to 99 seconds.' do
        Array(http["keepalive_timeout"]).each do |http_alive|
          expect(http_alive[0].to_i).to(be > 9)
          expect(http_alive[0].to_i).to(be < 100)
        end
      end
    end
    # Within server
    describe 'The server context keep-alive value' do
      it 'should be from 10 to 99 seconds.' do
        Array(nginx_conf(conf_path).servers).each do |server|
          Array(server.params["keepalive_timeout"]).each do |server_alive|
            expect(server_alive[0].to_i).to(be > 9)
            expect(server_alive[0].to_i).to(be < 100)
          end
        end
      end
    end
    # Within location
    describe 'The  location context keep-alive value' do
      it 'should be from 10 to 99 seconds.' do
        Array(nginx_conf(conf_path).locations).each do |location|
          Array(location.params["keepalive_timeout"]).each do |location_alive|
            expect(location_alive[0].to_i).to(be > 9)
            expect(location_alive[0].to_i).to(be < 100)
          end
        end
      end
    end
  end
end

