# encoding: UTF-8

control "V-55973" do
  title "The NGINX web server must use a logging mechanism that is configured to
alert the ISSO and SA in the event of a processing failure."
  desc  "Reviewing log data allows an investigator to recreate the path of an
attacker and to capture forensic data for later use. Log data is also essential
to system administrators in their daily administrative duties on the hosted
system or within the hosted applications.

    If the logging system begins to fail, events will not be recorded.
Organizations shall define logging failure events, at which time the
application or the logging mechanism the application utilizes will provide a
warning to the ISSO and SA at a minimum.
  "
  desc  "rationale", ""
  desc  "check", "
  Review the NGINX web server documentation and deployment configuration settings
  to determine if the web server logging system provides an alert to the ISSO and
  the SA at a minimum when a processing failure occurs.

  Work with the SIEM administrator to determine if an alert is configured when audit 
  data is no longer received as expected.

  If there is no alert configured, this is a finding.
  "
  desc  "fix", "Work with the SIEM administrator to configure an alert when no audit 
  data is received from NGINX based on the defined schedule of connections
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000108-WSR-000166"
  tag "gid": "V-55973"
  tag "rid": "SV-70227r2_rule"
  tag "stig_id": "SRG-APP-000108-WSR-000166"
  tag "fix_id": "F-60851r2_fix"
  tag "cci": ["CCI-000139"]
  tag "nist": ["AU-5 a", "Rev_4"]

  describe "Manual Check" do
    skip "Work with the SIEM administrator to determine if an alert is configured when audit 
    data is no longer received as expected. 
    If there is no alert configured, this is a finding."
  end
end

