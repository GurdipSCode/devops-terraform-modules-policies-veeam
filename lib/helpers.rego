package lib.helpers

import rego.v1

# Extract all planned resource changes from a Terraform plan
planned_resources(plan) := [rc |
	some rc in plan.resource_changes
	rc.change.actions[_] != "no-op"
]

# Filter resources by type
resources_by_type(plan, resource_type) := [rc |
	some rc in planned_resources(plan)
	rc.type == resource_type
]

# Get all restapi_object resources (primary Veeam resource type)
restapi_objects(plan) := resources_by_type(plan, "restapi_object")

# Parse JSON data field from restapi_object
# The 'data' attribute in restapi_object is a JSON string
parse_resource_data(resource) := parsed if {
	data_str := resource.change.after.data
	parsed := json.unmarshal(data_str)
}

parse_resource_data(resource) := {} if {
	not resource.change.after.data
}

# Get the API path for a restapi_object
resource_path(resource) := resource.change.after.path

# Check if a path matches a pattern (e.g., /jobs/*, /credentials/*)
path_matches(resource_path, pattern) if {
	glob.match(pattern, ["/"], resource_path)
}

# Extract provider config from the Terraform plan
provider_configs(plan) := plan.configuration.provider_config

# Get restapi provider config
restapi_provider_config(plan) := config if {
	some name, config in provider_configs(plan)
	startswith(name, "restapi")
}

# Check if a value looks like a hardcoded secret (not a variable reference)
is_hardcoded(value) if {
	is_string(value)
	not startswith(value, "var.")
	not contains(value, "${")
	not contains(value, "data.")
	not contains(value, "local.")
	count(value) > 0
}

# Check if a string contains any pattern from a list
contains_any(str, patterns) if {
	some pattern in patterns
	contains(lower(str), lower(pattern))
}

# Extract port from URI string
extract_port(uri) := port if {
	parts := split(uri, ":")
	count(parts) == 3
	port_and_path := parts[2]
	port_str := split(port_and_path, "/")[0]
	port := to_number(port_str)
}

extract_port(uri) := 443 if {
	startswith(uri, "https://")
	parts := split(uri, ":")
	count(parts) == 2
}

extract_port(uri) := 80 if {
	startswith(uri, "http://")
	parts := split(uri, ":")
	count(parts) == 2
}
