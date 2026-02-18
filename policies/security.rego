package security

import data.lib.helpers
import rego.v1

# ============================================================================
# TLS / TRANSPORT SECURITY
# ============================================================================

# DENY: restapi provider configured with insecure TLS
deny contains msg if {
	data.security.allow_insecure_tls == false

	some name, provider in input.configuration.provider_config
	startswith(name, "restapi")

	some expr in provider.expressions.insecure
	expr.constant_value == true

	msg := sprintf(
		"INSECURE_TLS: Provider '%s' has insecure = true. TLS verification must not be disabled. Use a trusted CA or configure root_ca_file.",
		[name],
	)
}

# DENY: Provider URI using HTTP instead of HTTPS
deny contains msg if {
	data.security.require_https == true

	some name, provider in input.configuration.provider_config
	startswith(name, "restapi")

	some expr in provider.expressions.uri
	uri := expr.constant_value
	startswith(uri, "http://")

	msg := sprintf(
		"NO_HTTPS: Provider '%s' uses HTTP (%s). All API connections must use HTTPS.",
		[name, uri],
	)
}

# DENY: Provider using non-standard API port
deny contains msg if {
	some name, provider in input.configuration.provider_config
	startswith(name, "restapi")

	some expr in provider.expressions.uri
	uri := expr.constant_value
	port := helpers.extract_port(uri)
	allowed_ports := data.security.allowed_api_ports

	not port in allowed_ports

	msg := sprintf(
		"NON_STANDARD_PORT: Provider '%s' connects on port %d. Allowed ports: %v",
		[name, port, allowed_ports],
	)
}

# ============================================================================
# CREDENTIAL SECURITY
# ============================================================================

# DENY: Hardcoded passwords/secrets in restapi_object data
deny contains msg if {
	data.security.block_hardcoded_credentials == true

	some rc in helpers.restapi_objects(input)
	parsed := helpers.parse_resource_data(rc)

	# Walk the parsed data to find sensitive-looking fields
	[path, value] := walk(parsed)
	some field in path
	is_string(field)
	helpers.contains_any(field, data.security.sensitive_field_patterns)
	is_string(value)
	helpers.is_hardcoded(value)

	msg := sprintf(
		"HARDCODED_SECRET: Resource '%s' contains a potentially hardcoded secret in field '%s'. Use Terraform variables, Vault, or environment variables instead.",
		[rc.address, concat(".", [p | some p in path; is_string(p)])],
	)
}

# DENY: Hardcoded credentials in provider headers (e.g., Authorization header)
deny contains msg if {
	data.security.block_hardcoded_credentials == true

	some name, provider in input.configuration.provider_config
	startswith(name, "restapi")

	some expr in provider.expressions.headers
	some header_name, header_val in expr.constant_value
	lower(header_name) == "authorization"

	msg := sprintf(
		"HARDCODED_AUTH_HEADER: Provider '%s' has a hardcoded Authorization header. Use variable references or external data sources for tokens.",
		[name],
	)
}

# DENY: Hardcoded username/password in provider config
deny contains msg if {
	data.security.block_hardcoded_credentials == true

	some name, provider in input.configuration.provider_config
	startswith(name, "restapi")

	some expr in provider.expressions.password
	expr.constant_value

	msg := sprintf(
		"HARDCODED_PASSWORD: Provider '%s' has a hardcoded password. Use var.password with sensitive = true or a secrets manager.",
		[name],
	)
}

# DENY: Cloud credentials (S3, Azure) with hardcoded access keys
deny contains msg if {
	data.security.block_hardcoded_credentials == true

	some rc in helpers.restapi_objects(input)
	helpers.path_matches(helpers.resource_path(rc), "/v1/cloudCredentials*")

	parsed := helpers.parse_resource_data(rc)
	key := parsed.accessKey
	helpers.is_hardcoded(key)

	msg := sprintf(
		"HARDCODED_CLOUD_KEY: Resource '%s' contains a hardcoded cloud access key. Use dynamic credential references.",
		[rc.address],
	)
}

# DENY: Cloud credentials with hardcoded secret keys
deny contains msg if {
	data.security.block_hardcoded_credentials == true

	some rc in helpers.restapi_objects(input)
	helpers.path_matches(helpers.resource_path(rc), "/v1/cloudCredentials*")

	parsed := helpers.parse_resource_data(rc)
	secret := parsed.secretKey
	helpers.is_hardcoded(secret)

	msg := sprintf(
		"HARDCODED_CLOUD_SECRET: Resource '%s' contains a hardcoded cloud secret key. Use dynamic credential references.",
		[rc.address],
	)
}

# ============================================================================
# API VERSION / HEADER SECURITY
# ============================================================================

# DENY: Missing x-api-version header
deny contains msg if {
	data.security.require_api_version_header == true

	some name, provider in input.configuration.provider_config
	startswith(name, "restapi")

	some expr in provider.expressions.headers
	headers := expr.constant_value
	not headers["x-api-version"]

	msg := sprintf(
		"MISSING_API_VERSION: Provider '%s' does not set the x-api-version header. This is required to ensure API compatibility.",
		[name],
	)
}

# ============================================================================
# RBAC / ACCESS CONTROL
# ============================================================================

# DENY: Credential resources being created without description/owner
deny contains msg if {
	some rc in helpers.restapi_objects(input)
	helpers.path_matches(helpers.resource_path(rc), "/v1/credentials*")

	parsed := helpers.parse_resource_data(rc)
	not parsed.description

	msg := sprintf(
		"CREDENTIAL_NO_DESCRIPTION: Resource '%s' creates a credential without a description. All credentials must include a description for audit purposes.",
		[rc.address],
	)
}

# DENY: Managed server additions without specifying credential type
deny contains msg if {
	some rc in helpers.restapi_objects(input)
	helpers.path_matches(helpers.resource_path(rc), "/v1/backupInfrastructure/managedServers*")

	parsed := helpers.parse_resource_data(rc)
	not parsed.credentials

	msg := sprintf(
		"SERVER_NO_CREDENTIALS: Resource '%s' adds a managed server without specifying credentials. All managed servers must reference stored credentials.",
		[rc.address],
	)
}

# ============================================================================
# NETWORK SECURITY
# ============================================================================

# DENY: Backup jobs targeting networks outside allowed ranges
deny contains msg if {
	some rc in helpers.restapi_objects(input)
	helpers.path_matches(helpers.resource_path(rc), "/v1/jobs*")

	parsed := helpers.parse_resource_data(rc)
	parsed.networkOptions
	parsed.networkOptions.enableNetworkThrottling == false

	msg := sprintf(
		"NO_NETWORK_THROTTLE: Resource '%s' has network throttling disabled. Enable throttling to prevent backup traffic from saturating production networks.",
		[rc.address],
	)
}

# ============================================================================
# WARN: Advisory security policies
# ============================================================================

# WARN: Provider not using test_path for connectivity validation
warn contains msg if {
	some name, provider in input.configuration.provider_config
	startswith(name, "restapi")
	not provider.expressions.test_path

	msg := sprintf(
		"NO_TEST_PATH: Provider '%s' does not set test_path. Consider setting test_path to validate API connectivity before applying changes.",
		[name],
	)
}

# WARN: No timeout configured on provider
warn contains msg if {
	some name, provider in input.configuration.provider_config
	startswith(name, "restapi")
	not provider.expressions.timeout

	msg := sprintf(
		"NO_TIMEOUT: Provider '%s' does not configure a timeout. Consider setting a timeout to prevent hanging API calls.",
		[name],
	)
}
