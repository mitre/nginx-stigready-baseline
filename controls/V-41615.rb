# encoding: UTF-8


control "V-41615" do
  title "The web server must produce log records containing sufficient
  information to establish the source of events."
  desc  "Web server logging capability is critical for accurate forensic
  analysis. Without sufficient and accurate information, a correct replay of the
  events cannot be determined.

    Ascertaining the correct source, e.g. source IP, of the events is important
  during forensic analysis. Correctly determining the source will add information
  to the overall reconstruction of the logable event. By determining the source
  of the event correctly, analysis of the enterprise can be undertaken to
  determine if the event compromised other assets within the enterprise.

    Without sufficient information establishing the source of the logged event,
  investigation into the cause of event is severely hindered. Log record content
  that may be necessary to satisfy the requirement of this control includes, but
  is not limited to, time stamps, source and destination IP addresses,
  user/process identifiers, event descriptions, application-specific events,
  success/fail indications, file names involved, access control, or flow control
  rules invoked.
  "
  
  desc  "check", "Review the NGINX web server documentation and deployment 
  configuration to determine if the NGINX web server is configured to generate 
  sufficient information to resolve the source, e.g. source IP, of the log event.


  Check for the following:
      # grep for a 'log_format' directive in the http context of the nginx.conf.
  
  If the 'log_format' directive is not configured to contain the '$remote_addr', 
  '$remote_user', and '$http_user_agent' variables, this is a finding. 
  "
  desc  "fix", "Configure the 'log_format' directive in the nginx.conf to use the 
  '$remote_user', '$remote_addr', and '$http_user_agent' variables to generate 
  the source of each logable event."

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000098-WSR-000059"
  tag "gid": "V-41615"
  tag "rid": "SV-54192r3_rule"
  tag "stig_id": "SRG-APP-000098-WSR-000059"
  tag "fix_id": "F-47074r2_fix"
  tag "cci": ["CCI-000133"]
  tag "nist": ["AU-3", "Rev_4"]

  nginx_conf_handle = nginx_conf(input('conf_path'))

  describe nginx_conf_handle do
    its ('params') { should_not be_empty }
  end

  # log_format - Context:	http
  nginx_conf_handle.params['http'].each do |http|
    http["log_format"].each do |log_format|
      describe 'remote_addr' do
        it 'should be part of every log format in http.' do
          expect(log_format.to_s).to(match /.*?\$remote_addr.*?/)
        end
      end
      describe 'remote_user' do
        it 'should be part of every log format in http.' do
          expect(log_format.to_s).to(match /.*?\$remote_user.*?/)
        end
      end
      describe 'http_user_agent' do
        it 'should be part of every log format in http.' do
          expect(log_format.to_s).to(match /.*?\$http_user_agent.*?/)
        end
      end
    end
  end
end

