# frozen_string_literal: true

# These actions describe desired state using action verbs, but are idempotent
# For example, the :delete function does nothing if no rule belonging to the rule group exists
# Group actions respect rule whitelist, but not group whitelist
resource_name :firewall_rule_group
provides :firewall_rule_group, os: 'windows'

property :firewall_name, String, default: 'default' # The name of the associated firewall

extend ::Firewall::Helper

action :enable do
  enable_helper(@new_resource)
end

action :disable do
  disable_helper(@new_resource)
end

action :delete do
  delete_helper(@new_resource)
end

action_class.class_eval do
  include ::Firewall::Helper

  def enable_helper(new_resource)
    verify_group_is_enabled(new_resource)
  end

  def disable_helper(new_resource)
    verify_group_is_disabled(new_resource)
  end

  def delete_helper(new_resource)
    verify_group_does_not_exist(new_resource)
  end
end
