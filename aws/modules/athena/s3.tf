resource "aws_kms_key" "athena_key" {
  description             = "KMS key for Athena data encryption"
  deletion_window_in_days = 30 # セキュリティポリシーに従い30日に設定
  enable_key_rotation     = true
}

resource "aws_kms_alias" "athena_key_alias" {
  name          = "alias/${var.project}-${var.environment}-athena"
  target_key_id = aws_kms_key.athena_key.key_id
}

resource "aws_s3_bucket" "data_bucket" {
  bucket              = format("%s-%s-data", var.project, var.environment)
  object_lock_enabled = true # ランサムウェアによるデータ即時破壊・改竄を防止
}

resource "aws_s3_bucket_versioning" "data_bucket_versioning" {
  bucket = aws_s3_bucket.data_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "data_bucket_lock" {
  bucket = aws_s3_bucket.data_bucket.id
  rule {
    default_retention {
      mode = "COMPLIANCE" # rootアカウントでも削除不可
      days = 90
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data_bucket_encryption" {
  bucket = aws_s3_bucket.data_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.athena_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "data_bucket_block" {
  bucket = aws_s3_bucket.data_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "data_bucket_lifecycle" {
  bucket = aws_s3_bucket.data_bucket.id

  rule {
    id     = "archive-old-data"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

resource "aws_s3_bucket" "athena_results_bucket" {
  bucket = format("%s-%s-athena-results", var.project, var.environment)
}

resource "aws_s3_bucket_server_side_encryption_configuration" "athena_results_encryption" {
  bucket = aws_s3_bucket.athena_results_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.athena_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "athena_results_block" {
  bucket = aws_s3_bucket.athena_results_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "athena_results_lifecycle" {
  bucket = aws_s3_bucket.athena_results_bucket.id

  rule {
    id     = "expire-old-results"
    status = "Enabled"

    expiration {
      days = 30
    }
  }
}
