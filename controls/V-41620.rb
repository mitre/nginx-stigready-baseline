# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-41620" do
  title "The web server must produce log records containing sufficient
information to establish the identity of any user/subject or process associated
with an event."
  desc  "Web server logging capability is critical for accurate forensic
analysis. Without sufficient and accurate information, a correct replay of the
events cannot be determined.

    Determining user accounts, processes running on behalf of the user, and
running process identifiers also enable a better understanding of the overall
event. User tool identification is also helpful to determine if events are
related to overall user access or specific client tools.

    Log record content that may be necessary to satisfy the requirement of this
control includes: time stamps, source and destination addresses, user/process
identifiers, event descriptions, success/fail indications, file names involved,
and access control or flow control rules invoked.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployment configuration to
determine if the web server can generate log data containing the user/subject
identity.

    Request a user access the hosted application and generate logable events,
and verify the events contain the user/subject or process identity.

    If the identity is not part of the log record, this is a finding.
  "
  desc  "fix", "Configure the web server to include the user/subject identity
or process as part of each log record."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000100-WSR-000064"
  tag "gid": "V-41620"
  tag "rid": "SV-54197r3_rule"
  tag "stig_id": "SRG-APP-000100-WSR-000064"
  tag "fix_id": "F-47079r2_fix"
  tag "cci": ["CCI-001487"]
  tag "nist": ["AU-3", "Rev_4"]

  Array(nginx_conf(conf_path).params['http']).each do |http|
    Array(http["log_format"]).each do |log_format|
      describe 'remote_user' do
        it 'should be part of every log format in http.' do
          expect(log_format.to_s).to(match /.*?\$remote_user.*?/)
        end
      end
    end
  end
end

