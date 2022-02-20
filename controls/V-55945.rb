control 'V-55945' do
  title "The NGINX web server must enforce approved authorizations for logical access
to hosted applications and resources in accordance with applicable access
control policies."
  desc  "To control access to sensitive information and hosted applications by
entities that have been issued certificates by DoD-approved PKIs, the web
server must be properly configured to incorporate a means of authorization that
does not simply rely on the possession of a valid certificate for access.
Access decisions must include a verification that the authenticated entity is
permitted to access the information or application. Authorization decisions
must leverage a variety of methods, such as mapping the validated PKI
certificate to an account with an associated set of permissions on the system.
If the web server relied only on the possession of the certificate and did not
map to system roles and privileges, each user would have the same abilities and
roles to make changes to the production system."

  desc  'check', "
  The NGINX web server must be configured to perform an authorization check to
  verify that the authenticated entity should be granted access to the requested
  content.

  If NGINX is not configured to serve files, this check is Not Applicable.

  Check for the following:
    #grep the 'auth_request' directive in the location context of the nginx.conf
    and any separated include configuration file.

  If the 'auth_request' directive does not exist inside the location context,
  this is a finding.
  "
  desc  'fix', "Configure server to use the 'auth_request' directive in the
  NGINX configuration file(s) to implement client authorization."

  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000033-WSR-000169'
  tag "gid": 'V-55945'
  tag "rid": 'SV-70199r2_rule'
  tag "stig_id": 'SRG-APP-000033-WSR-000169'
  tag "fix_id": 'F-60823r1_fix'
  tag "cci": ['CCI-000213']
  tag "nist": %w(AC-3)

  # List of all auth_request uris in the configuration files
  auth_uris = []

  if nginx_conf.locations.nil?
    impact 0.0
    describe 'This check is NA because NGINX has not been configured to serve files.' do
      skip 'This check is NA because NGINX has not been configured to serve files.'
    end
  else
    nginx_conf.locations.entries.each do |location|
      auth_uris.push(location.params['auth_request']) unless location.params['auth_request'].nil?
    end
    describe 'The uris collected from the auth_request directives' do
      it 'should not be an empty list.' do
        expect(auth_uris).to_not(be_empty)
      end
    end
    if auth_uris.empty?
      describe 'This test is skipped because the auth_request directive has not been configured for locations.' do
        skip 'This test is skipped because the auth_request directive has not been configured for locations.'
      end
    else
      auth_uris.flatten!.uniq!
      nginx_conf.locations.each do |location|
        auth_uris.each do |uri|
          next if location.params['_'].flatten.include?(uri)

          describe 'Each location context' do
            it 'should include an auth_request directive.' do
              expect(location.params).to(include 'auth_request')
            end
          end
        end
      end
    end
  end
end
