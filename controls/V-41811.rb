# encoding: UTF-8
conf_path = input('conf_path')
mime_type_path = input('mime_type_path')
access_log_path = input('access_log_path')
error_log_path = input('error_log_path')
password_path = input('password_path')
key_file_path = input('key_file_path')

control "V-41811" do
  title "The web server must be built to fail to a known safe state if system
initialization fails, shutdown fails, or aborts fail."
  desc  "Determining a safe state for failure and weighing that against a
potential DoS for users depends on what type of application the web server is
hosting. For an application presenting publicly available information that is
not critical, a safe state for failure might be to shut down for any type of
failure; but for an application that presents critical and timely information,
a shutdown might not be the best state for all failures.

    Performing a proper risk analysis of the hosted applications and
configuring the web server according to what actions to take for each failure
condition will provide a known fail safe state for the web server.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the web server documentation, deployed configuration, and risk
analysis documentation to determine whether the web server will fail to known
states for system initialization, shutdown, or abort failures.

    If the web server will not fail to known state, this is a finding.
  "
  desc  "fix", "Configure the web server to fail to the states of operation
during system initialization, shutdown, or abort failures found in the risk
analysis."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000225-WSR-000140"
  tag "gid": "V-41811"
  tag "rid": "SV-54388r3_rule"
  tag "stig_id": "SRG-APP-000225-WSR-000140"
  tag "fix_id": "F-47270r3_fix"
  tag "cci": ["CCI-001190"]
  tag "nist": ["SC-24", "Rev_4"]

  describe "Skip Test" do
    skip "This is a manual check"
  end
  
end

