# frozen_string_literal: true

firewall 'default' do
  action :create
end

firewall 'default' do
  action :log_scripts
end
