# encoding: UTF-8
conf_path = input('conf_path')


control "V-55979" do
  title "The NGINX web server must generate log records that can be mapped to
Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT)."
  desc  "If time stamps are not consistently applied and there is no common
time reference, it is difficult to perform forensic analysis across multiple
devices and log records.

    Time stamps generated by the web server include date and time. Time is
commonly expressed in Coordinated Universal Time (UTC), a modern continuation
of Greenwich Mean Time (GMT), or local time with an offset from UTC.
  "
  desc  "rationale", ""
  desc  "check", "
  Review the NGINX web server documentation and configuration to determine the time
  stamp format for log data.

  Check for the following:
      # grep for all 'env' directives in the main context of the nginx.conf.

  If neither 'env TZ=UTC' or 'env TZ=GMT' exists, this is a finding.
  "
  desc  "fix", "Configure the 'TZ' environment variable in the nginx.conf to store 
  log data time stamps in a format that is mappted to UTC or GMT time.

  Example configuration:
  'env TZ=UTC;' 
  or
  'env TZ=GMT;'"
  
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000374-WSR-000172"
  tag "gid": "V-55979"
  tag "rid": "SV-70233r2_rule"
  tag "stig_id": "SRG-APP-000374-WSR-000172"
  tag "fix_id": "F-60857r1_fix"
  tag "cci": ["CCI-001890"]
  tag "nist": ["AU-8 b", "Rev_4"]

  nginx_conf_handle = nginx_conf(conf_path)

  describe nginx_conf_handle do
    its ('params') { should_not be_empty }
  end

  found_utc_gmt = false;
  describe "In the nginx.conf file" do
    it 'the TZ environment variable should be set.' do
      expect(nginx_conf_handle.params['env']).to_not(cmp nil)
    end
  end

  Array(nginx_conf_handle.params['env']).each do |env|
    found_utc_gmt = false
    Array(env).each do |value|
      if (value == "TZ=UTC" || value == "TZ=GMT")
        found_utc_gmt = true
      end
    end
    describe "The TZ environment variable" do
      it 'should be set to UTC or GMT time.' do
        expect(found_utc_gmt).to(cmp true)
      end
    end
  end
end
