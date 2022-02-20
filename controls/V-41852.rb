control 'V-41852' do
  title 'The NGINX web server must limit the character set used for data entry.'
  desc  "Invalid user input occurs when a user inserts data or characters into
a hosted application's data entry field and the hosted application is
unprepared to process that data. This results in unanticipated application
behavior, potentially leading to an application compromise. Invalid user input
is one of the primary methods employed when attempting to compromise an
application.

    An attacker can also enter Unicode into hosted applications in an effort to
break out of the document home or root home directory or to bypass security
checks.

    The web server, by defining the character set available for data entry, can
trap efforts to bypass security checks or to compromise an application.
  "

  desc 'check', "Review the NGINX web server documentation and deployed configuration
  to determine what the data set is for data entry.

  If there are no websites configured or if NGINX is not configured to serve files,
  this check is Not Applicable.

  Check for the following:
      # grep the 'charset' directive in the http, server, and location context of
      the nginx.conf and any separated include configuration file.

  If the 'charset' directive does not exist or is not configured to use the charsets expected by the
  host application, this is a finding.
  "
  desc 'fix', "Configure the NGINX web server to include the 'charset' directive
  and use the character sets the application expects."

  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000251-WSR-000157'
  tag "gid": 'V-41852'
  tag "rid": 'SV-54429r3_rule'
  tag "stig_id": 'SRG-APP-000251-WSR-000157'
  tag "fix_id": 'F-47311r2_fix'
  tag "cci": ['CCI-001310']
  tag "nist": %w(SI-10)

  if nginx_conf.params['http'].nil?
    impact 0.0
    describe 'This check is NA because no websites have been configured.' do
      skip 'This check is NA because no websites have been configured.'
    end
  else
    nginx_conf.params['http'].each do |http|
      describe 'Charset directive' do
        it 'should exist and be configured to the expected value in the http context.' do
          expect(http).to(include 'charset')
          expect(http['charset'].join).to(cmp(input('charset_required')))
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
      describe 'Charset' do
        it 'should be configured to the expected value if found in the server context.' do
          expect(server.params['charset'].join).to(cmp(input('charset_required'))) unless server.params['charset'].nil?
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
      describe 'Charset' do
        it 'should be configured to the expected value if found in the location context.' do
          unless location.params['charset'].nil?
            expect(location.params['charset'].join).to(cmp(input('charset_required')))
          end
        end
      end
    end
  end
end
