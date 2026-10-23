mock_provider "aws" {
  override_data {
    target = data.aws_region.current
    values = {
      region = "eu-central-1"
    }
  }

  override_data {
    target = data.aws_caller_identity.current
    values = {
      account_id = "123456789012"
    }
  }
}

variables {
  okta_client_id     = "0oa123"
  okta_client_secret = "secret"
  okta_issuer        = "https://acme.okta.com"
}

run "login_function" {
  command = plan

  assert {
    condition     = aws_lambda_function.login.runtime == "nodejs22.x" && aws_lambda_function.login.handler == "index.handler"
    error_message = "Unexpected runtime or handler"
  }

  assert {
    condition     = aws_lambda_function.login.memory_size >= 512
    error_message = "The login function needs enough CPU for a cold start well inside CloudFront's origin timeout"
  }

  assert {
    condition     = aws_lambda_function.login.function_name == "cloudfront-okta-auth"
    error_message = "Default name not applied"
  }

  assert {
    condition     = aws_lambda_function_url.login.authorization_type == "AWS_IAM"
    error_message = "The function URL must only be reachable through CloudFront origin access control"
  }

  assert {
    condition     = aws_lambda_function.login.environment[0].variables.SESSION_KEY_VERSION == "1"
    error_message = "A session key rotation must recycle the function's containers"
  }
}

run "gate_function" {
  command = plan

  assert {
    condition     = aws_cloudfront_function.gate.runtime == "cloudfront-js-2.0" && aws_cloudfront_function.gate.publish == true
    error_message = "The gate must be a published cloudfront-js-2.0 function"
  }

  assert {
    condition     = strcontains(aws_cloudfront_function.gate.code, "import cf from \"cloudfront\";") && strcontains(aws_cloudfront_function.gate.code, "async function handler(event)")
    error_message = "The gate must import the KVS helper and define the handler"
  }

  assert {
    condition     = strcontains(aws_cloudfront_function.gate.code, "function rewrite(request) { return request; }")
    error_message = "The default rewrite must be embedded"
  }

  assert {
    condition     = length(aws_cloudfront_function.gate.code) < 10240
    error_message = "CloudFront Functions are limited to 10 KB of code"
  }
}

run "custom_rewrite" {
  command = plan

  variables {
    viewer_request_rewrite = "function rewrite(request) { request.uri = '/docs' + request.uri; return request; }"
  }

  assert {
    condition     = strcontains(aws_cloudfront_function.gate.code, "request.uri = '/docs' + request.uri;")
    error_message = "viewer_request_rewrite must be embedded in the gate"
  }
}

run "iam_role" {
  command = plan

  assert {
    condition     = strcontains(aws_iam_role.login.assume_role_policy, "lambda.amazonaws.com") && !strcontains(aws_iam_role.login.assume_role_policy, "edgelambda")
    error_message = "Role must be assumable by lambda.amazonaws.com only"
  }

  assert {
    condition     = strcontains(aws_iam_role_policy.login.policy, "arn:aws:logs:eu-central-1:123456789012:log-group:/aws/lambda/cloudfront-okta-auth:*")
    error_message = "Log permissions must cover the function's log group"
  }

  assert {
    condition     = strcontains(aws_iam_role_policy.login.policy, "ssm:GetParameters") && strcontains(aws_iam_role_policy.login.policy, "parameter/cloudfront-okta-auth/session-key")
    error_message = "Role must be able to read both parameters"
  }
}

run "client_secret_parameter" {
  command = plan

  assert {
    condition     = aws_ssm_parameter.okta_client_secret.type == "SecureString"
    error_message = "Client secret must be a SecureString"
  }

  assert {
    condition     = aws_ssm_parameter.okta_client_secret.name == "/cloudfront-okta-auth/okta-client-secret"
    error_message = "Unexpected parameter name"
  }

  assert {
    condition     = aws_ssm_parameter.okta_client_secret.value_wo_version == 1
    error_message = "Secret version marker must default to 1"
  }
}

run "session_key_parameter" {
  command = plan

  assert {
    condition     = aws_ssm_parameter.session_key.type == "SecureString" && aws_ssm_parameter.session_key.name == "/cloudfront-okta-auth/session-key"
    error_message = "Session key must be a SecureString under the name prefix"
  }

  assert {
    condition     = aws_ssm_parameter.session_key.value_wo_version == 1
    error_message = "Session key version marker must default to 1"
  }
}

run "session_key_rotation" {
  command = plan

  variables {
    session_key_version = 3
  }

  assert {
    condition     = aws_ssm_parameter.session_key.value_wo_version == 3 && aws_lambda_function.login.environment[0].variables.SESSION_KEY_VERSION == "3"
    error_message = "session_key_version must rewrite the parameter and recycle the function"
  }
}

run "secret_rotation_bumps_version" {
  command = plan

  variables {
    okta_client_secret_version = 2
  }

  assert {
    condition     = aws_ssm_parameter.okta_client_secret.value_wo_version == 2
    error_message = "value_wo_version must follow okta_client_secret_version"
  }
}

run "org_authorization_server_endpoints" {
  command = plan

  assert {
    condition     = output.okta_endpoints.authorize == "https://acme.okta.com/oauth2/v1/authorize"
    error_message = "Org authorization server endpoints live under /oauth2/v1"
  }

  assert {
    condition     = output.okta_endpoints.token == "https://acme.okta.com/oauth2/v1/token"
    error_message = "Unexpected token endpoint"
  }

  assert {
    condition     = anytrue([for s in data.archive_file.this.source : strcontains(s.content, "\"authorize_endpoint\":\"https://acme.okta.com/oauth2/v1/authorize\"")])
    error_message = "Rendered config.mjs must contain the derived authorize endpoint"
  }

  assert {
    condition     = anytrue([for s in data.archive_file.this.source : strcontains(s.content, "\"issuer\":\"https://acme.okta.com\"")])
    error_message = "Rendered config.mjs must contain the issuer verbatim for iss validation"
  }
}

run "custom_authorization_server_endpoints" {
  command = plan

  variables {
    okta_issuer = "https://acme.okta.com/oauth2/default"
  }

  assert {
    condition     = output.okta_endpoints.authorize == "https://acme.okta.com/oauth2/default/v1/authorize"
    error_message = "Custom authorization server endpoints live under the issuer"
  }

  assert {
    condition     = output.okta_endpoints.keys == "https://acme.okta.com/oauth2/default/v1/keys"
    error_message = "Unexpected JWKS endpoint"
  }
}

run "paths_and_bundle" {
  command = plan

  assert {
    condition     = output.login_path == "/_auth/login" && output.callback_path == "/_auth/callback" && output.logout_path == "/_auth/logout" && output.auth_path_pattern == "/_auth/*"
    error_message = "Unexpected auth paths"
  }

  assert {
    condition     = anytrue([for s in data.archive_file.this.source : strcontains(s.content, "\"session_ttl_seconds\":28800")])
    error_message = "Rendered config.mjs must carry the default 8 h session lifetime"
  }

  assert {
    condition     = toset([for s in data.archive_file.this.source : s.filename]) == toset(["index.mjs", "auth.mjs", "config.mjs"])
    error_message = "Bundle must contain exactly index.mjs, auth.mjs and config.mjs"
  }
}

run "custom_name" {
  command = plan

  variables {
    name = "docs-auth"
  }

  assert {
    condition     = aws_lambda_function.login.function_name == "docs-auth" && aws_iam_role.login.name == "docs-auth-login" && aws_ssm_parameter.okta_client_secret.name == "/docs-auth/okta-client-secret" && aws_cloudfront_function.gate.name == "docs-auth" && aws_cloudfront_key_value_store.this.name == "docs-auth"
    error_message = "name must be applied to the functions, key value store, role and parameters"
  }
}
