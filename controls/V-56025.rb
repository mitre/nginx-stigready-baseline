control 'V-56025' do
  title "Cookies exchanged between the NGINX web server and client, such as session
  cookies, must have security settings that disallow cookie access outside the
  originating web server and hosted application."
  desc "Cookies are used to exchange data between the web server and the
  client. Cookies, such as a session cookie, may contain session information and
  user credentials used to maintain a persistent connection between the user and
  the hosted application since HTTP/HTTPS is a stateless protocol.

    When the cookie parameters are not set properly (i.e., domain and path
  parameters), cookies can be shared within hosted applications residing on the
  same web server or to applications hosted on different web servers residing on
  the same domain.
  "

  desc 'check', "Review the NGINX web server documentation and configuration to
  determine if cookies between the web server and client are accessible by applications
  or web servers other than the originating pair.

  If it is determined that the web server is not required to perform session management,
  this check is Not Applicable.

  If NGINX is not configured to serve files or if the required directive(s)
  cannot be found in the NGINX configuration files, this check is Not Applicable.

  Check for the following:
    # grep the 'proxy_cookie_path' directive in the location context
    of the nginx.conf and any separated include configuration file.

  If the 'proxy_cookie_path' directive exists and is not set to the 'HTTPOnly' and
  'Secure' properties, this is a finding.

    # grep ‘proxy_cookie_domain’ directive in the location context
    of the nginx.conf and any separated include configuration file.

  If the 'proxy_cookie_domain' directive is found and not set to 'off', this is a finding.
  "
  desc 'fix', "If the 'proxy_cookie_path' directive exists in the NGINX configuration
  file(s), configure it to include the 'HTTPOnly' and 'Secure' properties.

  Example:
  proxy_cookie_path / '/; HTTPOnly; Secure';

  Ensure the 'proxy_cookie_domain' directive is set to 'off' if it exists."
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000223-WSR-000011'
  tag "gid": 'V-56025'
  tag "rid": 'SV-70279r2_rule'
  tag "stig_id": 'SRG-APP-000223-WSR-000011'
  tag "fix_id": 'F-60903r1_fix'
  tag "cci": ['CCI-001664']
  tag "nist": ['SC-23 (3)', '']

  if input('performs_session_management') == false
    impact 0.0
    describe 'This check is NA because session management is not required.' do
      skip 'This check is NA because session management is not required.'
    end
  elsif nginx_conf.servers.nil?
    impact 0.0
    describe 'This check is NA because NGINX has not been configured to serve files.' do
      skip 'This check is NA because NGINX has not been configured to serve files.'
    end
  else
    nginx_conf.locations.each do |location|
      if location.params['proxy_cookie_path'].nil?
        impact 0.0
        describe 'This check is NA because the proxy_cookie_path directive is not configured.' do
          skip 'This check is NA because the proxy_cookie_path directive is not configured.'
        end
      else
        describe "The 'proxy_cookie_path'" do
          it 'should be configured to HTTPOnly and Secure' do
            expect(location.params['proxy_cookie_path'].join).to(include '/; HTTPOnly; Secure')
          end
        end
      end
    end
  end
end
