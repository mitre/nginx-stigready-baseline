# encoding: UTF-8

control "V-41620" do
  title "The web server must produce log records containing sufficient
  information to establish the identity of any user/subject or process associated
  with an event."
  desc  "Web server logging capability is critical for accurate forensic
  analysis. Without sufficient and accurate information, a correct replay of the
  events cannot be determined.

    Determining user accounts, processes running on behalf of the user, and
  running process identifiers also enable a better understanding of the overall
  event. User tool identification is also helpful to determine if events are
  related to overall user access or specific client tools.

    Log record content that may be necessary to satisfy the requirement of this
  control includes: time stamps, source and destination addresses, user/process
  identifiers, event descriptions, success/fail indications, file names involved,
  and access control or flow control rules invoked.
  "
  desc  "check", "Review the NGINX web server documentation and deployment 
  configuration to determine if the web server can generate log data containing 
  the user/subject identity.

  Check for the following:
      # grep for a 'log_format' directive in the http context of the nginx.conf.

  If the 'log_format' directive is not configured to contain the '$remote_user' 
  variable, this is a finding. 
  "
  desc  "fix", "
  Configure the 'log_format' directive in the nginx.conf to use the '$remote_user' 
  variable to to include the user/subject identity or process as part of each log record."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000100-WSR-000064"
  tag "gid": "V-41620"
  tag "rid": "SV-54197r3_rule"
  tag "stig_id": "SRG-APP-000100-WSR-000064"
  tag "fix_id": "F-47079r2_fix"
  tag "cci": ["CCI-001487"]
  tag "nist": ["AU-3", "Rev_4"]

  nginx_conf_handle = nginx_conf(input('conf_path'))

  describe nginx_conf_handle do
    its ('params') { should_not be_empty }
  end

  nginx_conf_handle.params['http'].each do |http|
    http["log_format"].each do |log_format|
      describe 'remote_user' do
        it 'should be part of every log format in http.' do
          expect(log_format.to_s).to(match /.*?\$remote_user.*?/)
        end
      end
    end
  end
end

