control "V-41699" do
  title "The web server must have Multipurpose Internet Mail Extensions (MIME)
that invoke OS shell programs disabled."
  desc  "Controlling what a user of a hosted application can access is part of
the security posture of the web server. Any time a user can access more
functionality than is needed for the operation of the hosted application poses
a security issue. A user with too much access can view information that is not
needed for the user's job role, or the user could use the function in an
unintentional manner.

    A MIME tells the web server what type of program various file types and
extensions are and what external utilities or programs are needed to execute
the file type.

    A shell is a program that serves as the basic interface between the user
and the operating system, so hosted application users must not have access to
these programs. Shell programs may execute shell escapes and can then perform
unauthorized activities that could damage the security posture of the web
server.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000141-WSR-000081"
  tag "gid": "V-41699"
  tag "rid": "SV-54276r3_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000081"
  tag "fix_id": "F-47158r2_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
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
  tag "check": "Review the web server documentation and deployment
configuration to determine if the OS shell is accessible by any MIME types that
are enabled.

If a user of the web server can invoke OS shell programs, this is a finding."
  tag "fix": "Configure the web server to disable all MIME types that invoke OS
shell programs."
end

