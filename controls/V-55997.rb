control 'V-55997' do
  title "The NGINX web server must be tuned to handle the operational requirements of
the hosted application."
  desc  "A Denial of Service (DoS) can occur when the web server is so
overwhelmed that it can no longer respond to additional requests. A web server
not properly tuned may become overwhelmed and cause a DoS condition even with
expected traffic from users. To avoid a DoS, the web server must be tuned to
handle the expected traffic for the hosted applications."

  desc  'check', "Review the NGINX web server documentation and deployed configuration
  to determine what parameters are set to tune the web server.

  If there are no websites configured or if NGINX is not configured to serve files,
  this check is Not Applicable.

  To view the timeout values enter the following commands:
    # grep ''client_body_timeout'' on the nginx.conf file and any separate included
    configuration files
    # grep ''client_header_timeout'' on the nginx.conf file and any separate included
    configuration files

  If the values of each are not set to 10 seconds (10s) or less, this is a finding.'
  "
  desc 'fix', "Configure the NGINX web server to include the 'client_body_timeout' and
  'client_header_timeout' directives in the NGINX configuration file(s).
  Set the value of 'client_body_timeout' and 'client_header_timeout to be
  10 seconds or less to mitigate the effects of several types of denial of
  service attacks:

  client_body_timeout   10s;
  client_header_timeout 10s;
  "
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000435-WSR-000148'
  tag "gid": 'V-55997'
  tag "rid": 'SV-70251r2_rule'
  tag "stig_id": 'SRG-APP-000435-WSR-000148'
  tag "fix_id": 'F-60875r2_fix'
  tag "cci": ['CCI-002385']
  tag "nist": %w(SC-5 Rev_4)

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
          expect(server.params['client_header_timeout'].join.to_i).to(be <= 10) unless server.params['client_header_timeout'].nil?
        end
      end
      describe 'The server context client_body_timeout value' do
        it 'should be set to 10 (seconds) or less, if found' do
          expect(server.params['client_body_timeout'].join.to_i).to(be <= 10) unless server.params['client_body_timeout'].nil?
        end
      end
    end
  end
end
