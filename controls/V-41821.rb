control "V-41821" do
  title "The web server document directory must be in a separate partition from
the web servers system files."
  desc  "A web server is used to deliver content on the request of a client.
The content delivered to a client must be controlled, allowing only hosted
application files to be accessed and delivered. To allow a client access to
system files of any type is a major security risk that is entirely avoidable.
Obtaining such access is the goal of directory traversal and URL manipulation
vulnerabilities. To facilitate such access by misconfiguring the web document
(home) directory is a serious error. In addition, having the path on the same
drive as the system folder compounds potential attacks such as drive space
exhaustion."
  impact 0.5
  tag "gtitle": "SRG-APP-000233-WSR-000146"
  tag "gid": "V-41821"
  tag "rid": "SV-54398r3_rule"
  tag "stig_id": "SRG-APP-000233-WSR-000146"
  tag "fix_id": "F-47280r2_fix"
  tag "cci": ["CCI-001084"]
  tag "nist": ["SC-3", "Rev_4"]
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
to determine where the document directory is located for each hosted
application.

If the document directory is not in a separate partition from the web server's
system files, this is a finding."
  tag "fix": "Configure the web server to place the document directories in a
separate partition from the web server system files."
end

