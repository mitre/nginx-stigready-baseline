control 'V-55949' do
  title 'The NGINX web server must set an inactive timeout for sessions.'
  desc  "Leaving sessions open indefinitely is a major security risk. An
attacker can easily use an already authenticated session to access the hosted
application as the previously authenticated user. By closing sessions after a
set period of inactivity, the web server can make certain that those sessions
that are not closed through the user logging out of an application are
eventually closed.

    Acceptable values are 5 minutes for high-value applications, 10 minutes for
medium-value applications, and 20 minutes for low-value applications.
  "

  desc 'check', "Review the hosted applications, NGINX web server documentation
  and deployed configuration to verify that the web server will close an open session
  after a configurable time of inactivity.

  If there are no websites configured or if NGINX is not configured to serve files,
  this check is Not Applicable.

  To view the timeout values enter the following commands:

    # grep ''client_body_timeout'' on the nginx.conf file and any separate included
    configuration files

    # grep ''client_header_timeout'' on the nginx.conf file and any separate included
    configuration files

    # grep 'keepalive_timeout' in the nginx.conf and any separated include
        configuration file.

  If the values of the 'client_body_timeout' and 'client_header_timeout' directives are
  not set to 10 seconds (10s) or less,  this is a finding.

  If the value of  'keepalive_timeout' directive is not set to 5 (seconds) or less,
  this is a finding."

  desc 'fix', "Configure the NGINX web server to include the 'client_body_timeout',
  'client_header_timeout', and 'keepalive_timeout' in the NGINX configuration file(s).
  Set the value of 'client_body_timeout' and 'client_header_timeout to be 10 seconds or
  less. Set the value of 'keep_alive_timeout' to be 5 seconds or less.

  Example:
    client_body_timeout   10s;
    client_header_timeout 10s;
    keepalive_timout 5s 5s;"

  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000295-WSR-000134'
  tag "gid": 'V-55949'
  tag "rid": 'SV-70203r2_rule'
  tag "stig_id": 'SRG-APP-000295-WSR-000134'
  tag "fix_id": 'F-60827r1_fix'
  tag "cci": ['CCI-002361']
  tag "nist": %w(AC-12)

  if nginx_conf.params['http'].nil?
    impact 0.0
    describe 'This check is NA because no websites have been configured.' do
      skip 'This check is NA because no websites have been configured.'
    end
  else
    nginx_conf.params['http'].each do |http|
      describe 'The http context client_header_timeout value' do
        it 'should exist and should be set to 10 (seconds) or less.' do
          expect(http).to(include 'client_header_timeout')
          expect(http['client_header_timeout'].join.to_i).to(be <= 10)
        end
      end
      describe 'The http context client_body_timeout value' do
        it 'should exist and should be set to 10 (seconds) or less.' do
          expect(http).to(include 'client_body_timeout')
          expect(http['client_body_timeout'].join.to_i).to(be <= 10)
        end
      end
      describe 'The http context keep-alive value' do
        it 'should exist and should be set to 5 (seconds) or less.' do
          expect(http).to(include 'keepalive_timeout')
          http['keepalive_timeout'].each do |http_alive|
            expect(http_alive[0].to_i).to(be <= 5)
            expect(http_alive[1].to_i).to(be <= 5)
          end
        end
      end
    end
  end

  if nginx_conf.servers.nil?
    impact 0.0
    describe 'This check is NA because NGINX has not been configured to serve files.' do
      skip 'This check is NA because NGINX has not been configured to serve files.'
    end
  else
    nginx_conf.servers.each do |server|
      describe 'The server context client_header_timeout value' do
        it 'should be set to 10 (seconds) or less, if found.' do
          unless server.params['client_header_timeout'].nil?
            expect(server.params['client_header_timeout'].join.to_i).to(be <= 10)
          end
        end
      end
      describe 'The server context client_body_timeout value' do
        it 'should be set to 10 (seconds) or less, if found' do
          unless server.params['client_body_timeout'].nil?
            expect(server.params['client_body_timeout'].join.to_i).to(be <= 10)
          end
        end
      end
      describe 'The server context keep-alive value' do
        it 'should be set to 5 (seconds) or less, if found.' do
          unless server.params['keepalive_timeout'].nil?
            server.params['keepalive_timeout'].each do |server_alive|
              expect(server_alive[0].to_i).to(be <= 5)
              expect(server_alive[1].to_i).to(be <= 5)
            end
          end
        end
      end
    end
  end

  if nginx_conf.locations.nil?
    impact 0.0
    describe 'This check is NA because NGINX has not been configured to serve files.' do
      skip 'This check is NA because NGINX has not been configured to serve files.'
    end
  else
    nginx_conf.locations.each do |location|
      describe 'The location context keep-alive value' do
        it 'should be set to 5 (seconds) or less, if found.' do
          unless location.params['keepalive_timeout'].nil?
            location.params['keepalive_timeout'].each do |location_alive|
              expect(location_alive[0].to_i).to(be <= 5)
              expect(location_alive[1].to_i).to(be <= 5)
            end
          end
        end
      end
    end
  end
end
