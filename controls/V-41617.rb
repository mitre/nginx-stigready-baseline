# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-41617" do
  title "The web server must produce log records that contain sufficient
information to establish the outcome (success or failure) of events."
  desc  "Web server logging capability is critical for accurate forensic
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
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployment configuration to
determine if the web server is configured to generate the outcome (success or
failure) of the event.

    Request a user access the hosted application and generate logable events,
and then review the logs to determine if the outcome of the event can be
established.

    If the outcome of the event cannot be determined, this is a finding.
  "
  desc  "fix", "Configure the web server to generate the outcome, success or
failure, as part of each logable event."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000099-WSR-000061"
  tag "gid": "V-41617"
  tag "rid": "SV-54194r3_rule"
  tag "stig_id": "SRG-APP-000099-WSR-000061"
  tag "fix_id": "F-47076r2_fix"
  tag "cci": ["CCI-000134"]
  tag "nist": ["AU-3", "Rev_4"]

  Array(nginx_conf(conf_path).params['http']).each do |http|
    Array(http["log_format"]).each do |log_format|
      describe 'status' do
        it 'should be part of every log format in http.' do
          expect(log_format.to_s).to(match /.*?\$status.*?/)
        end
      end
    end
  end
end

