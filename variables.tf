variable "okta_client_id" {
  description = "Client ID of the Okta OIDC web application."
  type        = string

  validation {
    condition     = length(var.okta_client_id) > 0
    error_message = "okta_client_id must not be empty."
  }
}

variable "okta_client_secret" {
  description = "Client secret of the Okta OIDC web application. Ephemeral: written to an SSM SecureString parameter and never stored in state or plan. Bump okta_client_secret_version to rotate it."
  type        = string
  sensitive   = true
  ephemeral   = true

  validation {
    condition     = length(var.okta_client_secret) > 0
    error_message = "okta_client_secret must not be empty."
  }
}

variable "okta_client_secret_version" {
  description = "Version marker for okta_client_secret. Terraform only rewrites the SSM parameter when this value changes, so increment it whenever the secret is rotated."
  type        = number
  default     = 1

  validation {
    condition     = var.okta_client_secret_version >= 1 && floor(var.okta_client_secret_version) == var.okta_client_secret_version
    error_message = "okta_client_secret_version must be a positive integer."
  }
}

variable "okta_issuer" {
  description = "Okta issuer URL without trailing slash: the org authorization server (https://acme.okta.com) or a custom authorization server (https://acme.okta.com/oauth2/default)."
  type        = string

  validation {
    condition     = can(regex("^https://[^/]+(/oauth2/[^/]+)?$", var.okta_issuer))
    error_message = "okta_issuer must look like https://<domain> or https://<domain>/oauth2/<authServerId> with no trailing slash."
  }
}

variable "session_ttl_seconds" {
  description = "Lifetime of the session cookie issued after a successful login."
  type        = number
  default     = 28800

  validation {
    condition     = var.session_ttl_seconds >= 300 && var.session_ttl_seconds <= 604800 && floor(var.session_ttl_seconds) == var.session_ttl_seconds
    error_message = "session_ttl_seconds must be a whole number between 300 and 604800."
  }
}

variable "session_key_version" {
  description = "Version marker for the generated session signing key. Increment it to rotate the key, which signs everybody out once."
  type        = number
  default     = 1

  validation {
    condition     = var.session_key_version >= 1 && floor(var.session_key_version) == var.session_key_version
    error_message = "session_key_version must be a positive integer."
  }
}

variable "viewer_request_rewrite" {
  description = "JavaScript source defining `function rewrite(request)` for the CloudFront Function. It runs on every authenticated request and must return the request, for example after mapping directory paths to index.html. The default returns the request unchanged."
  type        = string
  default     = "function rewrite(request) { return request; }"

  validation {
    condition     = strcontains(var.viewer_request_rewrite, "function rewrite(")
    error_message = "viewer_request_rewrite must define function rewrite(request)."
  }
}

variable "name" {
  description = "Name of the CloudFront Function, key value store, login Lambda function, IAM role and SSM parameter prefix."
  type        = string
  default     = "cloudfront-okta-auth"

  validation {
    condition     = can(regex("^[a-zA-Z0-9_-]{1,58}$", var.name))
    error_message = "name must be 1-58 characters of letters, digits, hyphens or underscores."
  }
}

variable "tags" {
  description = "Tags applied to all resources that support them."
  type        = map(string)
  default     = {}
}
