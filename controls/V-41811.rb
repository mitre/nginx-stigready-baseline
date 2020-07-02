# encoding: UTF-8

control "V-41811" do
  title "The NGINX web server must be built to fail to a known safe state if system
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
  Review the NGINX web server documentation, deployed configuration, and risk
  analysis documentation to determine whether the web server will fail to known
  states for system initialization, shutdown, or abort failures.

  Interview the System Administrator for the NGINX web server.

  Ask for documentation on the disaster recovery methods tested and planned for 
  the NGINX web server in the event of the necessity for rollback.

  If documentation for a disaster recovery has not been established, this is a finding.
  "
  desc  "fix", "Prepare documentation for disaster recovery methods for the NGINX 
  web server in the event of the necessity for rollback.

  Document and test the disaster recovery methods designed."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000225-WSR-000140"
  tag "gid": "V-41811"
  tag "rid": "SV-54388r3_rule"
  tag "stig_id": "SRG-APP-000225-WSR-000140"
  tag "fix_id": "F-47270r3_fix"
  tag "cci": ["CCI-001190"]
  tag "nist": ["SC-24", "Rev_4"]

  describe "Manual Check" do
    skip "Interview the System Administrator for the NGINX web server.
    Ask for documentation on the disaster recovery methods tested and planned for 
    the NGINX web server in the event of the necessity for rollback.
    If documentation for a disaster recovery has not been established, this is a finding."
  end
  
end

