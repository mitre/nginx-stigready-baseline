# encoding: UTF-8

control "V-55951" do
  title "The NGINX web server must set an absolute timeout for sessions."
  desc  "Leaving sessions open indefinitely is a major security risk. An
attacker can easily use an already authenticated session to access the hosted
application as the previously authenticated user. By closing sessions after an
absolute period of time, the user is forced to re-authenticate guaranteeing the
session is still in use. Enabling an absolute timeout for sessions closes
sessions that are still active. Examples would be a runaway process accessing
the web server or an attacker using a hijacked session to slowly probe the web
server."
  desc  "rationale", ""
  desc  "check", "
  Review the NGINX web server documentation and deployed configuration to verify
  that the web server is configured to close sessions after an absolute period of
  time.

  To view the timeout values enter the following commands:

    # grep ''client_body_timeout'' on the nginx.conf file and any separate included configuration files

    # grep ''client_header_timeout'' on the nginx.conf file and any separate included configuration files

    # grep 'keepalive_timeout' in the nginx.conf and any separated include configuration file.

  If the values of the 'client_body_timeout' and 'client_header_timeout' directives are not set to 10 seconds (10s) or less,  this is a finding.

  If the value of  'keepalive_timeout' directive is not set to 5 (seconds) or less, this is a finding.
  "
  desc  "fix", "
  Configure the NGINX web server to include the 'client_body_timeout', 'client_header_timeout', and 'keepalive_timeout' in the NGINX configuration file(s). Set the value of 'client_body_timeout' and 'client_header_timeout to be 10 seconds or less. Set the value of 'keep_alive_timeout' to be 5 seconds or less. 

  Example:
    client_body_timeout   10s;
    client_header_timeout 10s;
    keepalive_timout 5s 5s;"

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000295-WSR-000012"
  tag "gid": "V-55951"
  tag "rid": "SV-70205r2_rule"
  tag "stig_id": "SRG-APP-000295-WSR-000012"
  tag "fix_id": "F-60829r1_fix"
  tag "cci": ["CCI-002361"]
  tag "nist": ["AC-12", "Rev_4"]

  nginx_conf_handle = nginx_conf(input('conf_path'))

  describe nginx_conf_handle do
    its ('params') { should_not be_empty }
  end
  
  # Within http
  Array(nginx_conf_handle.params['http']).each do |http|
    describe 'The http context client_header_timeout value' do
      it 'should exist and should be set to 10 (seconds) or less.' do
        expect(http).to(include "client_header_timeout")
        Array(http["client_header_timeout"]).each do |http_client_header|
          expect(http_client_header[0].to_i).to(be <= 10)
        end
      end
    end
    describe 'The http context client_body_timeout value' do
      it 'should exist and should be set to 10 (seconds) or less.' do
        expect(http).to(include "client_body_timeout")
        Array(http["client_body_timeout"]).each do |http_client_body|
          expect(http_client_body[0].to_i).to(be <= 10)
        end
      end
    end
    describe 'The http context keep-alive value' do
      it 'should exist and should be set to 5 (seconds) or less.' do
        expect(http).to(include "keepalive_timeout")
        Array(http["keepalive_timeout"]).each do |http_alive|
          expect(http_alive[0].to_i).to(be <= 5)
          expect(http_alive[1].to_i).to(be <= 5)
        end
      end
    end
  end

  # Within server
  Array(nginx_conf_handle.servers).each do |server|
    describe 'The server context client_header_timeout value' do
      it 'should exist and should be set to 10 (seconds) or less.' do
        expect(server.params).to(include "client_header_timeout")
        Array(server.params["client_header_timeout"]).each do |server_client_header|
          expect(server_client_header[0].to_i).to(be <= 10)
        end
      end
    end
    describe 'The server context client_body_timeout value' do
      it 'should exist and should be set to 10 (seconds) or less.' do
        expect(server.params).to(include "client_body_timeout")
        Array(server.params["client_body_timeout"]).each do |server_client_body|
          expect(server_client_body[0].to_i).to(be <= 10)
        end
      end
    end
    describe 'The server context keep-alive value' do
      it 'should exist and should be set to 5 (seconds) or less.' do
        expect(server.params).to(include "keepalive_timeout")
        Array(server.params["keepalive_timeout"]).each do |server_alive|
          expect(server_alive[0].to_i).to(be <= 5)
          expect(server_alive[1].to_i).to(be <= 5)
        end
      end
    end
  end

  # Within location
  Array(nginx_conf_handle.locations).each do |location|
    describe 'The location context keep-alive value' do
      it 'should exist and should be set to 5 (seconds) or less.' do
        expect(location.params).to(include "keepalive_timeout")
        Array(location.params["keepalive_timeout"]).each do |location_alive|
          expect(location_alive[0].to_i).to(be <= 5)
          expect(location_alive[1].to_i).to(be <= 5)
        end
      end
    end
  end
end

