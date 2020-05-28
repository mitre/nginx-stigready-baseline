# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-41612" do
  title "The web server must produce log records containing sufficient
information to establish what type of events occurred."
  desc  "Web server logging capability is critical for accurate forensic
analysis. Without sufficient and accurate information, a correct replay of the
events cannot be determined.

    Ascertaining the correct type of event that occurred is important during
forensic analysis. The correct determination of the event and when it occurred
is important in relation to other events that happened at that same time.

    Without sufficient information establishing what type of log event
occurred, investigation into the cause of event is severely hindered. Log
record content that may be necessary to satisfy the requirement of this control
includes, but is not limited to, time stamps, source and destination IP
addresses, user/process identifiers, event descriptions, application-specific
events, success/fail indications, file names involved, access control, or flow
control rules invoked.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployed configuration to determine
if the web server contains sufficient information to establish what type of
event occurred.

    Request a user access the hosted applications, and verify sufficient
information is recorded.

    If sufficient information is not logged, this is a finding.
  "
  desc  "fix", "Configure the web server to record sufficient information to
establish what type of events occurred."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000095-WSR-000056"
  tag "gid": "V-41612"
  tag "rid": "SV-54189r3_rule"
  tag "stig_id": "SRG-APP-000095-WSR-000056"
  tag "fix_id": "F-47071r2_fix"
  tag "cci": ["CCI-000130"]
  tag "nist": ["AU-3", "Rev_4"]

  # Is including the request information sufficient enough?

    # log_format - Context:	http
    Array(nginx_conf(conf_path).params['http']).each do |http|
      Array(http["log_format"]).each do |log_format|
        describe 'request' do
          # it { should match /.*?\$request.*?/ }
          it 'should be part of every log format in the http context.' do
            expect(log_format.to_s).to(match /.*?\$request.*?/)
          end
        end
      end
    end  
  
end

