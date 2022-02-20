control 'V-41617' do
  title "The NGINX web server must produce log records that contain sufficient
  information to establish the outcome (success or failure) of events."
  desc "Web server logging capability is critical for accurate forensic
  analysis. Without sufficient and accurate information, a correct replay of the
  events cannot be determined.

    Ascertaining the success or failure of an event is important during
  forensic analysis. Correctly determining the outcome will add information to
  the overall reconstruction of the logable event. By determining the success or
  failure of the event correctly, analysis of the enterprise can be undertaken to
  determine if events tied to the event occurred in other areas within the
  enterprise.

    Without sufficient information establishing the success or failure of the
  logged event, investigation into the cause of event is severely hindered. The
  success or failure also provides a means to measure the impact of an event and
  help authorized personnel to determine the appropriate response. Log record
  content that may be necessary to satisfy the requirement of this control
  includes, but is not limited to, time stamps, source and destination IP
  addresses, user/process identifiers, event descriptions, application-specific
  events, success/fail indications, file names involved, access control, or flow
  control rules invoked.
  "
  desc 'check', "Review the NGINX web server documentation and deployment
  configuration to determine if the web server is configured to generate the
  outcome (success or failure) of the event.

  If there are no websites configured for NGINX, this check is Not Applicable.

  Check for the following:
      # grep for a 'log_format' directive in the http context of the nginx.conf.

  If the 'log_format' directive is not configured to contain the '$status' variable,
  this is a finding.
  "
  desc 'fix', "Configure the 'log_format' directive in the nginx.conf to use the
  '$status' variable to generate the outcome, success or failure, as part of each
  logable event."

  impact 0.5
  tag "severity": 'medium'
  tag "gtitle": 'SRG-APP-000099-WSR-000061'
  tag "gid": 'V-41617'
  tag "rid": 'SV-54194r3_rule'
  tag "stig_id": 'SRG-APP-000099-WSR-000061'
  tag "fix_id": 'F-47076r2_fix'
  tag "cci": ['CCI-000134']
  tag "nist": %w(AU-3)

  if nginx_conf.params['http'].nil?
    impact 0.0
    describe 'This check is NA because no websites have been configured.' do
      skip 'This check is NA because no websites have been configured.'
    end
  else
    nginx_conf.params['http'].each do |http|
      http['log_format'].each do |log_format|
        describe 'status' do
          it 'should be part of every log format in http.' do
            expect(log_format.to_s).to(match(/.*?\$status.*?/))
          end
        end
      end
    end
  end
end
