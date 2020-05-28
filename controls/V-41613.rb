# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-41613" do
  title "The web server must produce log records containing sufficient
information to establish when (date and time) events occurred."
  desc  "Web server logging capability is critical for accurate forensic
analysis. Without sufficient and accurate information, a correct replay of the
events cannot be determined.

    Ascertaining the correct order of the events that occurred is important
during forensic analysis. Events that appear harmless by themselves might be
flagged as a potential threat when properly viewed in sequence. By also
establishing the event date and time, an event can be properly viewed with an
enterprise tool to fully see a possible threat in its entirety.

    Without sufficient information establishing when the log event occurred,
investigation into the cause of event is severely hindered. Log record content
that may be necessary to satisfy the requirement of this control includes, but
is not limited to, time stamps, source and destination IP addresses,
user/process identifiers, event descriptions, application-specific events,
success/fail indications, file names involved, access control, or flow control
rules invoked.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployment configuration to
determine if the web server is configured to generate a date and time for each
logged event.

    Request a user access the hosted application and generate logable events,
and then review the logs to determine if the date and time are included in the
log event data.

    If the date and time are not included, this is a finding.
  "
  desc  "fix", "Configure the web server to log date and time with the event."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000096-WSR-000057"
  tag "gid": "V-41613"
  tag "rid": "SV-54190r3_rule"
  tag "stig_id": "SRG-APP-000096-WSR-000057"
  tag "fix_id": "F-47072r2_fix"
  tag "cci": ["CCI-000131"]
  tag "nist": ["AU-3", "Rev_4"]

    # log_format - Context:	http
    Array(nginx_conf(conf_path).params['http']).each do |http|
      Array(http["log_format"]).each do |log_format|
        describe 'time_local' do
          # it { should match /.*?\$time_local.*?/ }
          it 'should be part of every log format in the http context.' do
            expect(log_format.to_s).to(match /.*?\$time_local.*?/)
          end
        end
      end
    end  
end


