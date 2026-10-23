#!/usr/bin/env bash
set -euo pipefail

etag=$(aws cloudfront-keyvaluestore describe-key-value-store --kvs-arn "$KVS_ARN" --query ETag --output text)
aws cloudfront-keyvaluestore put-key \
  --kvs-arn "$KVS_ARN" \
  --key "$KEY_NAME" \
  --value "$KEY_VALUE" \
  --if-match "$etag" \
  --query ETag --output text >/dev/null
