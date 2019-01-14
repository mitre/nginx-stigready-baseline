control "V-41702" do
  title "The web server must have Web Distributed Authoring (WebDAV) disabled."
  desc  "A web server can be installed with functionality that, just by its
nature, is not secure. Web Distributed Authoring (WebDAV) is an extension to
the HTTP protocol that, when developed, was meant to allow users to create,
change, and move documents on a server, typically a web server or web share.
Allowing this functionality, development, and deployment is much easier for web
authors.

    WebDAV is not widely used and has serious security concerns because it may
allow clients to modify unauthorized files on the web server.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000141-WSR-000085"
  tag "gid": "V-41702"
  tag "rid": "SV-54279r3_rule"
  tag "stig_id": "SRG-APP-000141-WSR-000085"
  tag "fix_id": "F-47161r2_fix"
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
configuration to determine if Web Distributed Authoring (WebDAV) is enabled.

If WebDAV is enabled, this is a finding."
  tag "fix": "Configure the web server to disable Web Distributed Authoring."
end

