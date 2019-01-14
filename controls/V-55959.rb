control "V-55959" do
  title "The web server must use a logging mechanism that is configured to
allocate log record storage capacity large enough to accommodate the logging
requirements of the web server."
  desc  "In order to make certain that the logging mechanism used by the web
server has sufficient storage capacity in which to write the logs, the logging
mechanism needs to be able to allocate log record storage capacity.

    The task of allocating log record storage capacity is usually performed
during initial installation of the logging mechanism. The system administrator
will usually coordinate the allocation of physical drive space with the web
server administrator along with the physical location of the partition and
disk. Refer to NIST SP 800-92 for specific requirements on log rotation and
storage dependent on the impact of the web server.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000357-WSR-000150"
  tag "gid": "V-55959"
  tag "rid": "SV-70213r2_rule"
  tag "stig_id": "SRG-APP-000357-WSR-000150"
  tag "fix_id": "F-60837r1_fix"
  tag "cci": ["CCI-001849"]
  tag "nist": ["AU-4", "Rev_4"]
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
configuration to determine if the web server is using a logging mechanism to
store log records. If a logging mechanism is in use, validate that the
mechanism is configured to use record storage capacity in accordance with
specifications within NIST SP 800-92 for log record storage requirements.

If the web server is not using a logging mechanism, or if the mechanism has not
been configured to allocate log record storage capacity in accordance with NIST
SP 800-92, this is a finding."
  tag "fix": "Configure the web server to use a logging mechanism that is
configured to allocate log record storage capacity in accordance with NIST SP
800-92 log record storage requirements."
end

