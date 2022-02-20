control 'V-55953' do
  title "Remote access to the NGINX web server must follow access policy or work in
conjunction with enterprise tools designed to enforce policy requirements."
  desc  "Remote access to the web server is any access that communicates
through an external, non-organization-controlled network. Remote access can be
used to access hosted applications or to perform management functions.

    A web server can be accessed remotely and must be able to enforce remote
access policy requirements or work in conjunction with enterprise tools
designed to enforce policy requirements.

    Examples of the web server enforcing a remote access policy are
implementing IP filtering rules, using https instead of http for communication,
implementing secure tokens, and validating users.
  "

  desc 'check', "Review the NGINX web server product documentation and deployed
  configuration to determine if the server or an enterprise tool is enforcing the
  organization's requirements for remote connections.

  If NGINX is not configured to serve files, this check is Not Applicable.

  If the an enterprise tools is enforcing the organization's requirements for remote
  connections, this control must be reviewed manually.

  If NGINX is enforcing the requirements for remote connections, check for the following:
      # grep for a 'deny' directive in the location context of the nginx.conf and any
      separated include configuration file.

  Verify that there is a 'deny all' set in each location context to deny all IP addresses
  by default and allow only approved IP addresses.

  If a 'deny all' is not set in each location, this is a finding.
  "
  desc 'fix', "Add a 'deny all' in each location context in the NGINX configuration
  file(s) to enforce the remote access policy.

  Then add 'allow' directive(s) in each location context in the NGINX configuration file(s)
  and configure it to only allow approved IP addresses."

  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000315-WSR-000003'
  tag "gid": 'V-55953'
  tag "rid": 'SV-70207r2_rule'
  tag "stig_id": 'SRG-APP-000315-WSR-000003'
  tag "fix_id": 'F-60831r2_fix'
  tag "cci": ['CCI-002314']
  tag "nist": ['AC-17 (1)', '']

  if input('uses_enterprise_tool') == 'true'
    describe "This test requires a Manual Review: Determine if the enterprise tool is enforcing
    the organization's requirements for remote connections." do
      skip "This test requires a Manual Review: Determine if the enterprise tool is enforcing
      the organization's requirements for remote connections."
    end
  elsif nginx_conf.locations.empty?
    impact 0.0
    describe 'This check is NA because NGINX has not been configured to serve files.' do
      skip 'This check is NA because NGINX has not been configured to serve files.'
    end
  else
    nginx_conf.locations.each do |location|
      deny_values = []
      deny_values.push(location.params['deny']) unless location.params['deny'].nil?
      describe 'Each location context' do
        it 'should include an deny all directive.' do
          expect(deny_values.to_s).to(include 'all')
        end
      end
    end
  end
end
