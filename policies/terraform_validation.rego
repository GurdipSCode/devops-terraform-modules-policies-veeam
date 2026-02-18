package terraform_validation

import data.lib.helpers
import rego.v1

# ============================================================================
# NAMING CONVENTIONS
# ============================================================================

# DENY: Resources not following naming convention
deny contains msg if {
	prefix := data.terraform_validation.required_name_prefix

	some rc in helpers.restapi_objects(input)
	name := rc.name

	not startswith(name, prefix)

	msg := sprintf(
		"NAMING_VIOLATION: Resource '%s' does not follow the naming convention. Name must start with '%s'.",
		[rc.address, prefix],
	)
}

# DENY: Backup job names in API data not following convention
deny contains msg if {
	prefix := data.terraform_validation.required_name_prefix

	some rc in helpers.restapi_objects(input)
	helpers.path_matches(helpers.resource_path(rc), "/v1/jobs*")

	parsed := helpers.parse_resource_data(rc)
	job_name := parsed.name

	not startswith(job_name, prefix)

	msg := sprintf(
		"JOB_NAMING_VIOLATION: Resource '%s' creates a backup job named '%s'. Job names must start with '%s'.",
		[rc.address, job_name, prefix],
	)
}

# ============================================================================
# RESOURCE LIMITS
# ============================================================================

# DENY: Too many restapi_object resources in a single plan
deny contains msg if {
	max_resources := data.terraform_validation.max_resources_per_module
	resources := helpers.restapi_objects(input)
	count(resources) > max_resources

	msg := sprintf(
		"TOO_MANY_RESOURCES: Plan contains %d restapi_object resources, maximum allowed is %d. Split into multiple modules.",
		[count(resources), max_resources],
	)
}

# ============================================================================
# RESOURCE CONFIGURATION HYGIENE
# ============================================================================

# DENY: restapi_object without a path configured
deny contains msg if {
	some rc in helpers.restapi_objects(input)
	not rc.change.after.path

	msg := sprintf(
		"MISSING_PATH: Resource '%s' does not have an API path configured.",
		[rc.address],
	)
}

# DENY: restapi_object with empty data payload
deny contains msg if {
	some rc in helpers.restapi_objects(input)
	rc.change.after.data == ""

	msg := sprintf(
		"EMPTY_DATA: Resource '%s' has an empty data payload. All Veeam API resources must include a valid JSON body.",
		[rc.address],
	)
}

# DENY: restapi_object data that is not valid JSON
deny contains msg if {
	some rc in helpers.restapi_objects(input)
	data_str := rc.change.after.data
	data_str != null
	data_str != ""
	not json.is_valid(data_str)

	msg := sprintf(
		"INVALID_JSON: Resource '%s' has a data field that is not valid JSON.",
		[rc.address],
	)
}

# ============================================================================
# DESCRIPTION / DOCUMENTATION
# ============================================================================

# DENY: Backup jobs without a description
deny contains msg if {
	some rc in helpers.restapi_objects(input)
	helpers.path_matches(helpers.resource_path(rc), "/v1/jobs*")

	parsed := helpers.parse_resource_data(rc)
	not parsed.description

	msg := sprintf(
		"JOB_NO_DESCRIPTION: Resource '%s' creates a backup job without a description. All jobs must include a description for documentation and audit.",
		[rc.address],
	)
}

# DENY: Repositories without a description
deny contains msg if {
	some rc in helpers.restapi_objects(input)
	helpers.path_matches(helpers.resource_path(rc), "/v1/backupInfrastructure/repositories*")

	parsed := helpers.parse_resource_data(rc)
	not parsed.description

	msg := sprintf(
		"REPO_NO_DESCRIPTION: Resource '%s' creates a repository without a description.",
		[rc.address],
	)
}

# ============================================================================
# DESTRUCTIVE ACTION GUARDS
# ============================================================================

# DENY: Deleting backup job resources (require manual approval)
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "restapi_object"
	rc.change.actions[_] == "delete"
	helpers.path_matches(rc.change.before.path, "/v1/jobs*")

	msg := sprintf(
		"DELETE_BLOCKED: Resource '%s' is scheduled for deletion. Backup job deletions must be approved manually. Remove the resource from state instead if decommissioning.",
		[rc.address],
	)
}

# DENY: Deleting repository resources
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "restapi_object"
	rc.change.actions[_] == "delete"
	helpers.path_matches(rc.change.before.path, "/v1/backupInfrastructure/repositories*")

	msg := sprintf(
		"REPO_DELETE_BLOCKED: Resource '%s' is scheduled for deletion. Repository deletions are blocked by policy. Remove from state if decommissioning.",
		[rc.address],
	)
}

# ============================================================================
# WARN: Advisory
# ============================================================================

# WARN: Large number of VMs in a single backup job
warn contains msg if {
	some rc in helpers.restapi_objects(input)
	helpers.path_matches(helpers.resource_path(rc), "/v1/jobs*")

	parsed := helpers.parse_resource_data(rc)
	vms := parsed.virtualMachines
	count(vms) > 20

	msg := sprintf(
		"LARGE_JOB: Resource '%s' has %d VMs in a single backup job. Consider splitting into multiple jobs for better management and performance.",
		[rc.address, count(vms)],
	)
}

# WARN: Using replace action on credentials (potential outage)
warn contains msg if {
	some rc in input.resource_changes
	rc.type == "restapi_object"
	rc.change.actions[_] == "delete"
	rc.change.actions[_] == "create"
	helpers.path_matches(rc.change.before.path, "/v1/cloudCredentials*")

	msg := sprintf(
		"CREDENTIAL_REPLACE: Resource '%s' is being replaced (delete+create). This may cause temporary backup failures. Consider using update instead.",
		[rc.address],
	)
}
