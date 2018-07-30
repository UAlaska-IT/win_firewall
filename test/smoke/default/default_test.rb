# frozen_string_literal: true


describe file('C:/chef/log/win_firewall.log') do
  it { should exist }
  it { should be_file }
end
