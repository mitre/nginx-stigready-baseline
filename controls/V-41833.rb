control 'V-41833' do
  title "The NGINX web server must restrict the ability of users to launch Denial of
Service (DoS) attacks against other information systems or networks."
  desc  "A web server can limit the ability of the web server being used in a
DoS attack through several methods. The methods employed will depend upon the
hosted applications and their resource needs for proper operation.

    An example setting that could be used to limit the ability of the web
server being used in a DoS attack is bandwidth throttling.
  "

  desc 'check', "Review the NGINX web server documentation and deployed configuration
  to determine whether the web server has been configured to limit the ability of the web
  server to be used in a DoS attack.

  If there are no websites configured or if NGINX is not configured to serve files,
  this check is Not Applicable.

  Check if there's a limit on the number of connections allowed and the bandwith allowed:
    #grep the 'limit_conn_zone' directive in the http context of the nginx.conf and any
    separated include configuration file.

    #grep the 'limit_conn' directive in the location context of the nginx.conf and any
    separated include configuration file.

    #grep the 'limit_rate' directive in the location context of the nginx.conf and any
    separated include configuration file.

  If the 'limit_conn_zone', 'limit_conn', 'limit_rate' directives are not configured to limit
  the number of simultanous sessions and bandwidth, or is unlimited, this is a finding.
  "
  desc 'fix', "Configure the NGINX web server to include the 'limit_conn_zone', 'limit_conn',
  'limit_rate' directives to limit the number of concurrent sessions and the bandwidth allowed."

  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000246-WSR-000149'
  tag "gid": 'V-41833'
  tag "rid": 'SV-54410r3_rule'
  tag "stig_id": 'SRG-APP-000246-WSR-000149'
  tag "fix_id": 'F-47292r2_fix'
  tag "cci": ['CCI-001094']
  tag "nist": ['SC-5 (1)', '']

  if nginx_conf.params['http'].nil?
    impact 0.0
    describe 'This check is NA because no websites have been configured.' do
      skip 'This check is NA because no websites have been configured.'
    end
  else
    nginx_conf.params['http'].each do |http|
      if http['limit_conn_zone'].nil?
        impact 0.0
        describe 'This test is NA because the limit_conn_zone directive has not been configured.' do
          skip 'This test is NA because limit_conn_zone directive has not been configured.'
        end
      else
        http['limit_conn_zone'].each do |limit_conn_zone|
          describe 'The limit_conn_zone' do
            it 'should include a client address.' do
              expect(limit_conn_zone.to_s).to(include '$binary_remote_addr')
            end
          end
          describe 'The limit_conn_zone' do
            it 'should include a zone.' do
              expect(limit_conn_zone.to_s).to(include 'zone=')
            end
          end
          limit_conn_zone.each do |value|
            next unless value.start_with?('zone')

            zone = value.split(':').last
            describe 'The zone in limit_conn_zone' do
              it 'should match this regex: .*?[0-9]{1,3}.*?' do
                expect(zone).to(match(/.*?[0-9]{1,3}.*?/))
              end
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
      if location.params['limit_conn'].nil?
        impact 0.0
        describe 'This test is NA because the limit_conn directive has not been configured.' do
          skip 'This test is NA because limit_conn directive has not been configured.'
        end
      else
        location.params['limit_conn'].each do |limit_conn|
          limit_conn.each do |value|
            describe 'The limit_conn setting' do
              it 'should match this regex: [a-zA-Z0-9]' do
                expect(value).to(match(/^[0-9a-zA-Z]*$/))
              end
            end
          end
        end
      end
      if location.params['limit_rate'].nil?
        impact 0.0
        describe 'This test is NA because the limit_rate directive has not been configured.' do
          skip 'This test is NA because limit_rate directive has not been configured.'
        end
      else
        location.params['limit_rate'].each do |limit_rate|
          Array(limit_rate).each do |value|
            describe 'The limit_rate setting' do
              it 'should match this regex: [a-zA-Z0-9]' do
                expect(value).to(match(/^[0-9a-zA-Z]*$/))
              end
            end
          end
        end
      end
    end
  end
end
