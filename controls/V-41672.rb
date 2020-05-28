# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-41672" do
  title "The log information from the web server must be protected from
unauthorized deletion."
  desc  "Log data is essential in the investigation of events. The accuracy of
the information is always pertinent. Information that is not accurate does not
help in the revealing of potential security risks and may hinder the early
discovery of a system compromise. One of the first steps an attacker will
undertake is the modification or deletion of audit records to cover his tracks
and prolong discovery.

    The web server must protect the log data from unauthorized deletion. This
can be done by the web server if the web server is also doing the logging
function. The web server may also use an external log system. In either case,
the logs must be protected from deletion by non-privileged users.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation and deployed configuration settings to
determine if the web server logging features protect log information from
unauthorized deletion.

    Review file system settings to verify the log files have secure file
permissions.

    If the web server log files are not protected from unauthorized deletion,
this is a finding.
  "
  desc  "fix", "Configure the web server log files so unauthorized deletion of
log information is not possible."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000120-WSR-000070"
  tag "gid": "V-41672"
  tag "rid": "SV-54249r3_rule"
  tag "stig_id": "SRG-APP-000120-WSR-000070"
  tag "fix_id": "F-47131r2_fix"
  tag "cci": ["CCI-000164"]
  tag "nist": ["AU-9", "Rev_4"]

  # Ensure access log is linked to stdout
  describe command('readlink ' + access_log_path) do
    its('stdout') { should eq "/dev/stdout\n" }
    # its('stdout') { should cmp '/proc/1/fd/pipe' }
  end
  # Ensure error log is linked to stderror
  describe command('readlink ' + error_log_path)do
    its('stdout') { should eq "/dev/stderr\n" }
    # its('stdout') { should cmp '/proc/1/fd/pipe' }
  end
  
end

