control "V-40799" do
  title "The web server must generate information to be used by external
applications or entities to monitor and control remote access."
  desc  "Remote access to the web server is any access that communicates
through an external, non-organization-controlled network. Remote access can be
used to access hosted applications or to perform management functions.

    By providing remote access information to an external monitoring system,
the organization can monitor for cyber attacks and monitor compliance with
remote access policies. The organization can also look at data organization
wide and determine an attack or anomaly is occurring on the organization which
might not be noticed if the data were kept local to the web server.

    Examples of external applications used to monitor or control access would
be audit log monitoring systems, dynamic firewalls, or infrastructure
monitoring systems.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000016-WSR-000005"
  tag "gid": "V-40799"
  tag "rid": "SV-53035r3_rule"
  tag "stig_id": "SRG-APP-000016-WSR-000005"
  tag "fix_id": "F-45961r2_fix"
  tag "cci": ["CCI-000067"]
  tag "nist": ["AC-17 (1)", "Rev_4"]
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
  tag "check": "Review the web server documentation and configuration to
determine if the web server is configured to generate information for external
applications monitoring remote access.

If a mechanism is not in place providing information to an external application
used to monitor and control access, this is a finding."
  tag "fix": "Configure the web server to provide remote connection information
to external monitoring and access control applications."
end

