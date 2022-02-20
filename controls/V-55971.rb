control 'V-55971' do
  title "The NGINX web server must be configurable to integrate with an organizations
security infrastructure."
  desc  "A web server will typically utilize logging mechanisms for maintaining
a historical log of activity that occurs within a hosted application. This
information can then be used for diagnostic purposes, forensics purposes, or
other purposes relevant to ensuring the availability and integrity of the
hosted application.

    While it is important to log events identified as being critical and
relevant to security, it is equally important to notify the appropriate
personnel in a timely manner so they are able to respond to events as they
occur.

    Manual review of the web server logs may not occur in a timely manner, and
each event logged is open to interpretation by a reviewer. By integrating the
web server into an overall or organization-wide log review, a larger picture of
events can be viewed, and analysis can be done in a timely and reliable manner.
  "

  desc 'check', "
  Review the NGINX web server documentation and deployed configuration to determine
  whether the web server is logging security-relevant events.

  If there are no websites configured for NGINX, this check is Not Applicable.

  Check for the following:
      # grep for 'access_log' and 'error_log' directives in the nginx.conf and
      any separated include configuration file.

  If the 'access_log' and 'error_log' directives cannot be found in NGINX configuration
  files, this check is Not Applicable.

  If the access.log and error.log files do not exist, this is a finding.
  "
  desc 'fix', "Execute the following command on the NGINX web server to link logs
  to stdout and stderr:
  # ln -sf /dev/stdout <access_log_path>/access.log
  # ln -sf /dev/stderr <access_log_path>/access.log

  Work with the SIEM administrator to integrate with an organizations security
  infrastructure."

  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000358-WSR-000163'
  tag "gid": 'V-55971'
  tag "rid": 'SV-70225r2_rule'
  tag "stig_id": 'SRG-APP-000358-WSR-000163'
  tag "fix_id": 'F-60849r1_fix'
  tag "cci": ['CCI-001851']
  tag "nist": ['AU-4 (1)', '']

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
  end
end
