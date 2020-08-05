# encoding: UTF-8

control "V-40791" do
  title "The NGINX web server must limit the number of allowed simultaneous session
  requests."
  desc  "Web server management includes the ability to control the number of
  users and user sessions that utilize a web server. Limiting the number of
  allowed users and sessions per user is helpful in limiting risks related to
  several types of Denial of Service attacks.

    Although there is some latitude concerning the settings themselves, the
  settings should follow DoD-recommended values, but the settings should be
  configurable to allow for future DoD direction. While the DoD will specify
  recommended values, the values can be adjusted to accommodate the operational
  requirement of a given system.
  "
  desc  "check", "Review the NGINX web server documentation and configuration to 
  determine if the number of simultaneous sessions is limited.

  If there are no websites configured or if NGINX is not configured to serve files, 
  this check is Not Applicable.

  Check for the following:
    # grep the 'limit_conn_zone' directive in the http context of the nginx.conf 
    and any separated include configuration file.
  
    # grep the 'limit_conn' directive in the location context of the nginx.conf 
    and any separated include configuration file.

  If the 'limit_conn_zone' and 'limit_conn' directives cannot be found in NGINX 
  configuration files, this check is Not Applicable. 
  
  If the 'limit_conn_zone' and 'limit_conn' directives are not configured to limit 
  the number of simultanous sessions or is unlimited, this is a finding. 
  "
  desc  "fix", "Configure the NGINX web server to include the 'limit_conn_zone' and 
  'limit_conn' directives in the NGINX configuration file(s) to limit the number of 
  concurrent sessions."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000001-WSR-000001"
  tag "gid": "V-40791"
  tag "rid": "SV-53018r3_rule"
  tag "stig_id": "SRG-APP-000001-WSR-000001"
  tag "fix_id": "F-45918r3_fix"
  tag "cci": ["CCI-000054"]
  tag "nist": ["AC-10", "Rev_4"]

  if nginx_conf.params['http'].nil?
    impact 0.0
    describe 'This check is NA because no websites have been configured.' do
      skip 'This check is NA because no websites have been configured.'
    end
  else 
    nginx_conf.params['http'].each do |http|
      if http["limit_conn_zone"].nil?
        impact 0.0
        describe 'This test is NA because the limit_conn_zone directive has not been configured.' do
          skip 'This test is NA because limit_conn_zone directive has not been configured.'
        end
      else
        http["limit_conn_zone"].each do |limit_conn_zone|
          describe 'The limit_conn_zone' do
            it 'should include a client address.' do
              expect(limit_conn_zone.to_s).to(include "$binary_remote_addr")
            end
          end
          describe 'The limit_conn_zone' do
            it 'should include a zone.' do
              expect(limit_conn_zone.to_s).to(include "zone=")
            end
          end
          limit_conn_zone.each do |value|
            if value.start_with?("zone")
              zone = value.split(":").last
              describe 'The zone in limit_conn_zone' do
                it 'should match this regex: .*?[0-9]{1,3}.*?' do
                  expect(zone).to(match /.*?[0-9]{1,3}.*?/)
                end
              end
            end
          end
        end
      end
    end
  end 
  # limit_conn - Context:	http, server, location

  if nginx_conf.locations.nil?
    impact 0.0
    describe 'This check is NA because NGINX has not been configured to serve files.' do
      skip 'This check is NA because NGINX has not been configured to serve files.'
    end
  else
    nginx_conf.locations.each do |location|
      if location.params["limit_conn"].nil?
        impact 0.0
        describe 'This test is NA because the limit_conn directive has not been configured.' do
          skip 'This test is NA because limit_conn directive has not been configured.'
        end
      else
        location.params["limit_conn"].each do |limit_conn|
          limit_conn.each do |value|
            describe 'The limit_conn setting' do
              it 'should match this regex: [a-zA-Z0-9]' do
                expect(value).to(match /^[0-9a-zA-Z]*$/)          
              end
            end
          end
        end
      end
    end
  end
end

