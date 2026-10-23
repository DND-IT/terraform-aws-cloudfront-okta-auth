provider "aws" {
  region = "eu-central-1"

  default_tags {
    tags = {
      Terraform  = "true"
      GithubRepo = "terraform-aws-cloudfront-okta-auth"
      GithubOrg  = "DND-IT"
      Example    = "complete"
    }
  }
}

resource "random_pet" "this" {
  length = 2
}

module "okta_auth" {
  source = "../../"

  name                       = "okta-auth-${random_pet.this.id}"
  okta_client_id             = var.okta_client_id
  okta_client_secret         = var.okta_client_secret
  okta_client_secret_version = var.okta_client_secret_version
  okta_issuer                = var.okta_issuer
}

resource "aws_s3_bucket" "site" {
  bucket        = "okta-auth-example-${random_pet.this.id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "site" {
  bucket                  = aws_s3_bucket.site.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "index" {
  bucket       = aws_s3_bucket.site.id
  key          = "index.html"
  content_type = "text/html"
  content      = "<html><body><h1>Hello from behind Okta</h1><a href=\"${module.okta_auth.logout_path}\">Sign out</a></body></html>"
}

resource "aws_s3_bucket_policy" "site" {
  bucket = aws_s3_bucket.site.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "cloudfront.amazonaws.com" }
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.site.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = aws_cloudfront_distribution.site.arn
          }
        }
      }
    ]
  })
}

resource "aws_cloudfront_origin_access_control" "login" {
  name                              = "okta-auth-example-login-${random_pet.this.id}"
  origin_access_control_origin_type = "lambda"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# CloudFront signs requests to the function URL; both actions are required.
resource "aws_lambda_permission" "login_url" {
  statement_id  = "AllowCloudFrontInvokeFunctionUrl"
  action        = "lambda:InvokeFunctionUrl"
  function_name = module.okta_auth.lambda_function_name
  principal     = "cloudfront.amazonaws.com"
  source_arn    = aws_cloudfront_distribution.site.arn
}

resource "aws_lambda_permission" "login" {
  statement_id  = "AllowCloudFrontInvokeFunction"
  action        = "lambda:InvokeFunction"
  function_name = module.okta_auth.lambda_function_name
  principal     = "cloudfront.amazonaws.com"
  source_arn    = aws_cloudfront_distribution.site.arn
}

data "aws_cloudfront_cache_policy" "caching_disabled" {
  name = "Managed-CachingDisabled"
}

data "aws_cloudfront_origin_request_policy" "all_viewer_except_host" {
  name = "Managed-AllViewerExceptHostHeader"
}

resource "aws_cloudfront_origin_access_control" "site" {
  name                              = "okta-auth-example-${random_pet.this.id}"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

data "aws_cloudfront_cache_policy" "caching_optimized" {
  name = "Managed-CachingOptimized"
}

resource "aws_cloudfront_distribution" "site" {
  enabled             = true
  comment             = "okta-auth-example-${random_pet.this.id}"
  default_root_object = "index.html"
  price_class         = "PriceClass_100"

  origin {
    origin_id                = "s3"
    domain_name              = aws_s3_bucket.site.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.site.id
  }

  origin {
    origin_id                = "login"
    domain_name              = module.okta_auth.function_url_domain
    origin_access_control_id = aws_cloudfront_origin_access_control.login.id

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  # The login endpoints go to the function URL. The gate still runs here: it lets
  # /_auth/* through and passes the viewer's host on for the OIDC redirect URI.
  ordered_cache_behavior {
    path_pattern             = module.okta_auth.auth_path_pattern
    target_origin_id         = "login"
    viewer_protocol_policy   = "https-only"
    allowed_methods          = ["GET", "HEAD", "OPTIONS"]
    cached_methods           = ["GET", "HEAD"]
    cache_policy_id          = data.aws_cloudfront_cache_policy.caching_disabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer_except_host.id

    function_association {
      event_type   = "viewer-request"
      function_arn = module.okta_auth.cloudfront_function_arn
    }
  }

  default_cache_behavior {
    target_origin_id       = "s3"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    cache_policy_id        = data.aws_cloudfront_cache_policy.caching_optimized.id
    compress               = true

    # The gate must be attached to every cache behavior, not only the default one.
    function_association {
      event_type   = "viewer-request"
      function_arn = module.okta_auth.cloudfront_function_arn
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}
