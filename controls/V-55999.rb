control "V-55999" do
  title "The web server must be protected from being stopped by a
non-privileged user."
  desc  "An attacker has at least two reasons to stop a web server. The first
is to cause a DoS, and the second is to put in place changes the attacker made
to the web server configuration.

    To prohibit an attacker from stopping the web server, the process ID (pid)
of the web server and the utilities used to start/stop the web server must be
protected from access by non-privileged users. By knowing the pid and having
access to the web server utilities, a non-privileged user has a greater
capability of stopping the server, whether intentionally or unintentionally.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000435-WSR-000147"
  tag "gid": "V-55999"
  tag "rid": "SV-70253r2_rule"
  tag "stig_id": "SRG-APP-000435-WSR-000147"
  tag "fix_id": "F-60877r1_fix"
  tag "cci": ["CCI-002385"]
  tag "nist": ["SC-5", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review the web server documentation and deployed configuration
to determine where the process ID is stored and which utilities are used to
start/stop the web server.

Determine whether the process ID and the utilities are protected from
non-privileged users.

If they are not protected, this is a finding."
  tag "fix": "Remove or modify non-privileged account access to the web server
process ID and the utilities used for starting/stopping the web server."
end

