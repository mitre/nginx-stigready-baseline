control "V-40791" do
  title "The web server must limit the number of allowed simultaneous session
requests."
  desc  "Web server management includes the ability to control the number of
users and user sessions that utilize a web server. Limiting the number of
allowed users and sessions per user is helpful in limiting risks related to
several types of Denial of Service attacks.

    Although there is some latitude concerning the settings themselves, the
settings should follow DoD-recommended values, but the settings should be
configurable to allow for future DoD direction. While the DoD will specify
recommended values, the values can be adjusted to accommodate the operational
requirement of a given system.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000001-WSR-000001"
  tag "gid": "V-40791"
  tag "rid": "SV-53018r3_rule"
  tag "stig_id": "SRG-APP-000001-WSR-000001"
  tag "fix_id": "F-45918r3_fix"
  tag "cci": ["CCI-000054"]
  tag "nist": ["AC-10", "Rev_4"]
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
determine if the number of simultaneous sessions is limited.

If the parameter is not configured or is unlimited, this is a finding."
  tag "fix": "Configure the web server to limit the number of concurrent
sessions."

  zones = nginx_conf.http.entries[0].params['limit_conn_zone'].flatten
  describe zones do
    it { should include "$binary_remote_addr" }
  end

  describe describe zones.find { |i| i.match? /default/ } do
    it { should_not be nil }
  end

  describe nginx_conf.http.entries[0].params['limit_conn'].flatten do
    it { should include 'default' }
  end

end

