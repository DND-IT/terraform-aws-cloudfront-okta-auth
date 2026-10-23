data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

locals {
  okta_base        = can(regex("/oauth2/", var.okta_issuer)) ? var.okta_issuer : "${var.okta_issuer}/oauth2"
  auth_prefix      = "/_auth/"
  login_path       = "/_auth/login"
  callback_path    = "/_auth/callback"
  logout_path      = "/_auth/logout"
  host_header      = "x-okta-auth-host"
  session_cookie   = "__Host-okta_session"
  session_key_name = "session_key"
  secret_param     = "/${var.name}/okta-client-secret"
  session_param    = "/${var.name}/session-key"

  okta_endpoints = {
    authorize = "${local.okta_base}/v1/authorize"
    token     = "${local.okta_base}/v1/token"
    keys      = "${local.okta_base}/v1/keys"
    logout    = "${local.okta_base}/v1/logout"
  }

  lambda_config = {
    issuer                  = var.okta_issuer
    client_id               = var.okta_client_id
    authorize_endpoint      = local.okta_endpoints.authorize
    token_endpoint          = local.okta_endpoints.token
    jwks_endpoint           = local.okta_endpoints.keys
    logout_endpoint         = local.okta_endpoints.logout
    login_path              = local.login_path
    callback_path           = local.callback_path
    logout_path             = local.logout_path
    client_secret_parameter = local.secret_param
    session_key_parameter   = local.session_param
    session_cookie          = local.session_cookie
    login_cookie            = "__Host-okta_login"
    id_token_cookie         = "__Secure-okta_id_token"
    session_ttl_seconds     = var.session_ttl_seconds
    host_header             = local.host_header
  }

  gate_config = {
    auth_prefix      = local.auth_prefix
    login_path       = local.login_path
    session_cookie   = local.session_cookie
    session_key_name = local.session_key_name
    host_header      = local.host_header
  }
}

resource "aws_ssm_parameter" "okta_client_secret" {
  name             = local.secret_param
  description      = "Okta client secret read by the ${var.name} login function"
  type             = "SecureString"
  value_wo         = var.okta_client_secret
  value_wo_version = var.okta_client_secret_version
  tags             = var.tags
}

ephemeral "random_password" "session_key" {
  length  = 64
  special = false
}

resource "aws_ssm_parameter" "session_key" {
  name             = local.session_param
  description      = "Key the ${var.name} login function signs session cookies with"
  type             = "SecureString"
  value_wo         = ephemeral.random_password.session_key.result
  value_wo_version = var.session_key_version
  tags             = var.tags
}

resource "aws_cloudfront_key_value_store" "this" {
  name    = var.name
  comment = "Session cookie key read by the ${var.name} CloudFront Function"
  tags    = var.tags
}

resource "terraform_data" "session_key" {
  triggers_replace = [aws_cloudfront_key_value_store.this.arn, var.session_key_version]

  provisioner "local-exec" {
    command = "${path.module}/scripts/put-session-key.sh"
    environment = {
      KVS_ARN   = aws_cloudfront_key_value_store.this.arn
      KEY_NAME  = local.session_key_name
      KEY_VALUE = ephemeral.random_password.session_key.result
    }
  }

  depends_on = [aws_ssm_parameter.session_key]
}

resource "aws_cloudfront_function" "gate" {
  name    = var.name
  comment = "Okta session gate"
  runtime = "cloudfront-js-2.0"
  publish = true

  code = templatefile("${path.module}/lambda/gate.js.tftpl", {
    config_json = jsonencode(local.gate_config)
    rewrite     = var.viewer_request_rewrite
    gate        = file("${path.module}/lambda/gate.js")
  })

  key_value_store_associations = [aws_cloudfront_key_value_store.this.arn]
  tags                         = var.tags
}

resource "aws_iam_role" "login" {
  name = "${var.name}-login"
  tags = var.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = "sts:AssumeRole"
        Principal = { Service = "lambda.amazonaws.com" }
      }
    ]
  })
}

resource "aws_iam_role_policy" "login" {
  name = "${var.name}-login"
  role = aws_iam_role.login.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.name}:*"
      },
      {
        Effect = "Allow"
        Action = "ssm:GetParameters"
        Resource = [
          for param in [local.secret_param, local.session_param] :
          "arn:aws:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter${param}"
        ]
      },
    ]
  })
}

data "archive_file" "this" {
  type             = "zip"
  output_path      = "${path.module}/builds/${var.name}.zip"
  output_file_mode = "0644"

  source {
    filename = "index.mjs"
    content  = file("${path.module}/lambda/index.mjs")
  }

  source {
    filename = "auth.mjs"
    content  = file("${path.module}/lambda/auth.mjs")
  }

  source {
    filename = "config.mjs"
    content  = templatefile("${path.module}/lambda/config.mjs.tftpl", { config_json = jsonencode(local.lambda_config) })
  }
}

resource "aws_lambda_function" "login" {
  function_name    = var.name
  description      = "Okta OIDC login, callback and logout behind CloudFront"
  role             = aws_iam_role.login.arn
  filename         = data.archive_file.this.output_path
  source_code_hash = data.archive_file.this.output_base64sha256
  handler          = "index.handler"
  runtime          = "nodejs22.x"
  architectures    = ["arm64"]
  memory_size      = 512
  timeout          = 15
  tags             = var.tags

  environment {
    variables = {
      SESSION_KEY_VERSION = tostring(var.session_key_version)
    }
  }

  depends_on = [aws_iam_role_policy.login]
}

resource "aws_lambda_function_url" "login" {
  function_name      = aws_lambda_function.login.function_name
  authorization_type = "AWS_IAM"
}

removed {
  from = aws_lambda_function.this

  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role.this

  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_iam_role_policy.this

  lifecycle {
    destroy = false
  }
}

removed {
  from = aws_ssm_parameter.client_secret

  lifecycle {
    destroy = false
  }
}
