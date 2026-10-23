output "cloudfront_function_arn" {
  description = "ARN of the CloudFront Function. Associate it as viewer-request with the default cache behavior, every protected ordered cache behavior and the auth_path_pattern behavior."
  value       = aws_cloudfront_function.gate.arn
}

output "key_value_store_arn" {
  description = "ARN of the CloudFront key value store holding the session signing key."
  value       = aws_cloudfront_key_value_store.this.arn
}

output "lambda_function_name" {
  description = "Name of the login Lambda function. Grant cloudfront.amazonaws.com lambda:InvokeFunctionUrl and lambda:InvokeFunction on it, scoped to the distribution ARN."
  value       = aws_lambda_function.login.function_name
}

output "lambda_function_arn" {
  description = "ARN of the login Lambda function."
  value       = aws_lambda_function.login.arn
}

output "lambda_role_arn" {
  description = "ARN of the login Lambda function's execution role."
  value       = aws_iam_role.login.arn
}

output "function_url_domain" {
  description = "Domain of the login Lambda function URL, for the CloudFront origin behind auth_path_pattern. The URL uses AWS_IAM auth, so the origin needs an origin access control of type lambda."
  value       = trimsuffix(trimprefix(aws_lambda_function_url.login.function_url, "https://"), "/")
}

output "auth_path_pattern" {
  description = "Path pattern of the cache behavior that routes the login endpoints to the function URL origin."
  value       = "${local.auth_prefix}*"
}

output "ssm_parameter_arns" {
  description = "ARNs of the SSM SecureString parameters holding the Okta client secret and the session signing key."
  value = {
    client_secret = aws_ssm_parameter.okta_client_secret.arn
    session_key   = aws_ssm_parameter.session_key.arn
  }
}

output "login_path" {
  description = "Path that starts the Okta login; takes the return path as the r query parameter."
  value       = local.login_path
}

output "callback_path" {
  description = "Path that must be registered in Okta as sign-in redirect URI: https://<site-domain><callback_path>."
  value       = local.callback_path
}

output "logout_path" {
  description = "Path that clears the session and signs the user out of Okta."
  value       = local.logout_path
}

output "session_cookie" {
  description = "Name of the session cookie. Its value is v1.<exp>.<base64url JSON with sub and email>.<base64url HMAC-SHA256 of the first three parts>, signed with the key in the session_key SSM parameter."
  value       = local.session_cookie
}

output "okta_endpoints" {
  description = "Okta endpoints derived from okta_issuer."
  value       = local.okta_endpoints
}
