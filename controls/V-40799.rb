control 'V-40799' do
  title "The NGINX web server must generate information to be used by external
  applications or entities to monitor and control remote access."
  desc "Remote access to the web server is any access that communicates
  through an external, non-organization-controlled network. Remote access can be
  used to access hosted applications or to perform management functions.

    By providing remote access information to an external monitoring system,
  the organization can monitor for cyber attacks and monitor compliance with
  remote access policies. The organization can also look at data organization
  wide and determine an attack or anomaly is occurring on the organization which
  might not be noticed if the data were kept local to the web server.

    Examples of external applications used to monitor or control access would
  be audit log monitoring systems, dynamic firewalls, or infrastructure
  monitoring systems.
  "
  desc 'check', "Review the NGINX web server documentation and configuration to
  determine if the web server is configured to generate information for external
  applications monitoring remote access.

  If there are no websites configured or if NGINX is not configured to serve files,
  this check is Not Applicable.

  Check for the following:
   # grep for 'access_log' and 'error_log' directives in the nginx.conf and any
   separated include configuration file.

  Execute the following commands:
   # file <path to access_log>/access.log
   # file <path to error_log>/error.log

  If the 'access_log' and 'error_log' directives cannot be found in NGINX configuration files,
  this check is Not Applicable.

  If the access.log and error.log files do not exist, this is a finding.

  Verify the following only if in Docker environment -

    Execute the following commands to verify that the NGINX web server is producing logs
    and linking them to stdout and stderr:

      # readlink <access_log_path>/access.log
      # readlink <error_log_path>/error.log

    If the access.log and error.log files are not linked to stdout and stderr,
    this is a finding.
  "
  desc 'fix', "Enable loggin on the NGINX web server by configuring the 'access_log'
  and 'error_log' directives in the NGINX configuration file(s).

  Execute the following command on the NGINX web server to link logs to stdout and stderr:
  # ln -sf /dev/stdout <access_log_path>/access.log
  # ln -sf /dev/stderr <error_log_path>/error.log"

  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000016-WSR-000005'
  tag "gid": 'V-40799'
  tag "rid": 'SV-53035r3_rule'
  tag "stig_id": 'SRG-APP-000016-WSR-000005'
  tag "fix_id": 'F-45961r2_fix'
  tag "cci": ['CCI-000067']
  tag "nist": ['AC-17 (1)', 'Rev_4']

  if nginx_conf.params['http'].nil?
    impact 0.0
    describe 'This check is NA because no websites have been configured.' do
      skip 'This check is NA because no websites have been configured.'
    end
  else
    nginx_conf.params['http'].each do |http|
      if http['access_log'].nil?
        impact 0.0
        describe 'This test is NA because the access_log directive has not been configured.' do
          skip 'This test is NA because access_log directive has not been configured.'
        end
      else
        http['access_log'].each do |access_log|
          access_log.each do |access_value|
            next unless access_value.include? 'access.log'
            describe file(access_value) do
              it 'The access log should exist.' do
                expect(subject).to(exist)
              end
            end
          end
        end
      end
    end

    if nginx_conf.params['error_log'].nil?
      impact 0.0
      describe 'This test is NA because the error_log directive has not been configured.' do
        skip 'This test is NA because error_log directive has not been configured.'
      end
    else
      nginx_conf.params['error_log'].each do |error_log|
        error_log.each do |error_value|
          next unless error_value.include? 'error.log'
          describe file(error_value) do
            it 'The error log should exist.' do
              expect(subject).to(exist)
            end
          end
        end
      end
    end
    # Logs are symlinks in docker container
    if virtualization.system == 'docker'
      describe command('readlink ' + input('access_log_path')) do
        its('stdout') { should eq "/dev/stdout\n" }
      end
      describe command('readlink ' + input('error_log_path')) do
        its('stdout') { should eq "/dev/stderr\n" }
      end
    end
  end
end
