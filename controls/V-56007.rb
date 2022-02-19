control 'V-56007' do
  title "Cookies exchanged between the web server and the client, such as
session cookies, must have cookie properties set to prohibit client-side
scripts from reading the cookie data."
  desc  "A cookie can be read by client-side scripts easily if cookie
properties are not set properly. By allowing cookies to be read by the
client-side scripts, information such as session identifiers could be
compromised and used by an attacker who intercepts the cookie. Setting cookie
properties (i.e. HttpOnly property) to disallow client-side scripts from
reading cookies better protects the information inside the cookie."

  desc  'check', "Review the NGINX web server documentation and deployed
  configuration to determine how to disable client-side scripts from reading
  cookies.

  If it is determined that the web server is not required to perform session
  management, this check is Not Applicable.

  If NGINX is not configured to serve files or if the required directive(s)
  cannot be found in the NGINX configuration files, this check is Not Applicable.

  Check for the following:
    # grep the 'proxy_cookie_path' directive in the location context of the
    nginx.conf and any separated include configuration file.

  If the 'proxy_cookie_path' directive exists and is not set to the 'HTTPOnly'
  property, this is a finding.
  "
  desc 'fix', "
  If the 'proxy_cookie_path' directive exists in the NGINX configuration file(s),
  configure it to include the 'HTTPOnly' property.

  Example:
  proxy_cookie_path / '/; HTTPOnly; Secure'"
  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000439-WSR-000154'
  tag "gid": 'V-56007'
  tag "rid": 'SV-70261r2_rule'
  tag "stig_id": 'SRG-APP-000439-WSR-000154'
  tag "fix_id": 'F-60885r1_fix'
  tag "cci": ['CCI-002418']
  tag "nist": %w(SC-8 Rev_4)

  if input('performs_session_management') == 'false'
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
