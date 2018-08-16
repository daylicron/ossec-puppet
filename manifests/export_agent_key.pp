#Export agent key
class ossec::export_agent_key($max_clients, $agent_name, $agent_ip_address) {

  # Babiel special:
  # Erzeugt eine agent_id. tauscht den Buchstaben
  # im Hostnamen gegen eine 1 (s) oder eine 2(n) aus.
  if $::hostname =~ /^s/ {
    $aid = regsubst($::hostname, '^s(\w{3,6})$', '1\1')
  } else {
    $aid = regsubst($::hostname, '^n(\w{2,6})$', '2\1')
  }
  ossec::agentkey{ "ossec_agent_${agent_name}_client":
    agent_id         => $aid,
    agent_name       => $agent_name,
    agent_ip_address => $agent_ip_address,
  }

  @@ossec::agentkey{ "ossec_agent_${agent_name}_server":
    agent_id         => $aid,
    agent_name       => $agent_name,
    agent_ip_address => $agent_ip_address
  }
}
