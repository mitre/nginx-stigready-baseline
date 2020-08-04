# encoding: UTF-8

control "V-55989" do
  title "The NGINX web server must not perform user management for hosted
  applications."
  desc  "User management and authentication can be an essential part of any
  application hosted by the web server. Along with authenticating users, the user
  management function must perform several other tasks like password complexity,
  locking users after a configurable number of failed logins, and management of
  temporary and emergency accounts; and all of this must be done enterprise-wide.

    The web server contains a minimal user management function, but the web
  server user management function does not offer enterprise-wide user management,
  and user management is not the primary function of the web server. User
  management for the hosted applications should be done through a facility that
  is built for enterprise-wide user management, like LDAP and Active Directory.
  "
  
  desc  "check", " Review the NGINX web server documentation and configuration 
  to determine if the web server is being used as a user management application.

  If there are no websites configured or if NGINX is not configured to serve files, 
  this check is Not Applicable.

  Check for the following:
  # grep 'auth_basic' and 'auth_basic_user_file' directive in the http, server, 
  and location context of the nginx.conf and any separated include configuration file.

  If the 'auth_basic' and 'auth_basic_user_file' directives exist, this is a finding.
  "
  desc  "fix", "Remove the 'auth_basic' and 'auth_basic_user_file' directives from the 
  http, server, and location contexts of the NGINX configuration file(s)."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-WSR-000015"
  tag "gid": "V-55989"
  tag "rid": "SV-70243r2_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000015"
  tag "fix_id": "F-60867r1_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]

  if nginx_conf.params['http'].nil?
    impact 0.0
    describe 'This check is NA because no websites have been configured.' do
      skip 'This check is NA because no websites have been configured.'
    end
  else 
    nginx_conf.params['http'].each do |http|
      describe 'http context:' do
        it 'There should not be an auth_basic directive.' do
          expect(http).to_not(include "auth_basic")
        end
        it 'There should not be an auth_basic_user_file directive.' do
          expect(http).to_not(include "auth_basic_user_file")
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
      describe 'server context:' do
        it 'There should not be an auth_basic directive.' do
          expect(server.params).to_not(include "auth_basic")
        end
        it 'There should not be an auth_basic_user_file directive.' do
          expect(server.params).to_not(include "auth_basic_user_file")
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
      describe "location context:" do
        it 'There should not be an auth_basic directive.' do
          expect(location.params).to_not(include "auth_basic")
        end
        it 'There should not be an auth_basic_user_file directive.' do
          expect(location.params).to_not(include "auth_basic_user_file")
        end
        location.params["limit_except"].each do |limit_except|
          describe "limit_except context:" do
            it 'There should not be an auth_basic directive.' do
              expect(limit_except).to_not(include "auth_basic")
            end
            it 'There should not be an auth_basic_user_file directive.' do
              expect(location.params).to_not(include "auth_basic_user_file")
            end
          end
        end unless location.params["limit_except"].nil?
      end
    end
  end
end

