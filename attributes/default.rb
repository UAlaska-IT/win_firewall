# frozen_string_literal: true

tcb = 'win_firewall'

# Attribute to provide a list of protected groups that will not be deleted
default[tcb]['firewall_to_whitelist_groups'] = {
  'default' => ['core networking']
}

# Attribute to provide a list of protected rules that will not be deleted
default[tcb]['firewall_to_whitelist_rules'] = {
  'default' => []
}
