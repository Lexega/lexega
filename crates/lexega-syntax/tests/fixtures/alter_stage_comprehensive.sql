-- Comprehensive ALTER STAGE test fixture
-- Tests all major ALTER STAGE operations including governance-relevant actions
-- Basic rename
ALTER STAGE my_stage RENAME TO new_stage_name;
-- Tag operations (governance)
ALTER STAGE my_stage SET TAG cost_center = 'engineering', environment = 'prod', owner = 'data-team';
ALTER STAGE my_stage UNSET TAG cost_center, environment;
-- Encryption operations (security governance - CRITICAL)
ALTER STAGE my_stage SET ENCRYPTION = (TYPE = 'AWS_SSE_KMS' KMS_KEY_ID = 'arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012');
ALTER STAGE secure_stage SET ENCRYPTION = (TYPE = 'AWS_SSE_S3');
ALTER STAGE insecure_stage SET ENCRYPTION = (TYPE = 'NONE');
-- URL changes
ALTER STAGE my_stage SET URL = 's3://my-bucket/path/to/data';
-- Credentials changes (security governance - HIGH)
ALTER STAGE my_stage SET CREDENTIALS = (AWS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE' AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
-- Storage integration changes (access control - MEDIUM)
ALTER STAGE my_stage SET STORAGE_INTEGRATION = my_s3_integration;
-- File format changes
ALTER STAGE my_stage SET FILE_FORMAT = (TYPE = CSV FIELD_DELIMITER = ',' SKIP_HEADER = 1 COMPRESSION = GZIP);
ALTER STAGE json_stage SET FILE_FORMAT = (TYPE = JSON);
-- Comment changes
ALTER STAGE my_stage SET COMMENT = 'Production data ingestion stage for customer data';
-- PrivateLink endpoint
ALTER STAGE my_stage SET USE_PRIVATELINK_ENDPOINT = TRUE;
ALTER STAGE public_stage SET USE_PRIVATELINK_ENDPOINT = FALSE;
-- Directory table operations (data discovery/compliance)
ALTER STAGE my_stage SET DIRECTORY = (ENABLE = TRUE);
ALTER STAGE my_stage SET DIRECTORY = (ENABLE = TRUE REFRESH_ON_CREATE = TRUE);
ALTER STAGE old_stage SET DIRECTORY = (ENABLE = FALSE);
-- Refresh operations
ALTER STAGE my_stage REFRESH;
ALTER STAGE my_stage REFRESH SUBPATH = 'data/2024/';
-- IF EXISTS variant
ALTER STAGE IF EXISTS maybe_stage REFRESH;
ALTER STAGE IF EXISTS conditional_stage SET TAG status = 'active';
-- Complex multi-operation scenarios
ALTER STAGE production_stage SET TAG criticality = 'high', compliance = 'pci-dss';
ALTER STAGE production_stage SET ENCRYPTION = (TYPE = 'AWS_SSE_KMS' KMS_KEY_ID = 'production-kms-key' MASTER_KEY = 'master-key-123');
ALTER STAGE production_stage SET STORAGE_INTEGRATION = prod_s3_integration;
ALTER STAGE production_stage SET COMMENT = 'Critical production stage - requires encryption and access controls';