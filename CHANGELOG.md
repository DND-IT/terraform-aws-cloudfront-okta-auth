# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0](https://github.com/DND-IT/terraform-aws-cloudfront-okta-auth/compare/v0.1.0...v0.2.0) (2026-10-23)

### ⚠ BREAKING CHANGES

* gate with a CloudFront Function and log in through a regional Lambda (#2)

### Features

* gate with a CloudFront Function and log in through a regional Lambda ([#2](https://github.com/DND-IT/terraform-aws-cloudfront-okta-auth/issues/2)) ([f8f1cce](https://github.com/DND-IT/terraform-aws-cloudfront-okta-auth/commit/f8f1cceb1e42afd2440076883bbf8cd94f59425a)), closes [tx-pts-dai/terraform-aws-cloudfront-okta-auth#1](https://github.com/tx-pts-dai/terraform-aws-cloudfront-okta-auth/issues/1)

## [0.1.0](https://github.com/tx-pts-dai/terraform-aws-cloudfront-okta-auth/compare/v0.0.0...v0.1.0) (2026-09-11)

### ⚠ BREAKING CHANGES

* requires Terraform >= 1.11 and an ephemeral value for
okta_client_secret.

Claude-Session: https://claude.ai/code/session_014cJLJTFGpVQarAGsnPZBzT
Signed-off-by: swibrow <15628653+swibrow@users.noreply.github.com>

### Features

* ephemeral client secret and pre-1.0 release rules ([50362fb](https://github.com/tx-pts-dai/terraform-aws-cloudfront-okta-auth/commit/50362fb9f0bbb4dc6e6d1c37ef91babbba3d979b))
