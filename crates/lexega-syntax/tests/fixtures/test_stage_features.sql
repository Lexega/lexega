-- CREATE STAGE Comprehensive Feature Test
-- Tests all Snowflake-documented CREATE STAGE syntax variants
-- ============================================================================
-- INTERNAL STAGES
-- ============================================================================
-- Minimal internal stage
CREATE STAGE int_minimal;
-- Internal stage with server-side encryption (SNOWFLAKE_SSE)
CREATE STAGE int_sse
    ENCRYPTION = (TYPE = 'SNOWFLAKE_SSE');
-- Internal stage with full encryption (SNOWFLAKE_FULL - default)
CREATE STAGE int_full_enc
    ENCRYPTION = (TYPE = 'SNOWFLAKE_FULL');
-- Internal stage with directory table
CREATE STAGE int_directory
    DIRECTORY = (
    ENABLE = TRUE
    AUTO_REFRESH = TRUE
  );
-- Internal stage with file format
CREATE STAGE int_csv
    FILE_FORMAT = (TYPE = CSV SKIP_HEADER = 1);
-- ============================================================================
-- EXTERNAL STAGES - AMAZON S3
-- ============================================================================
-- S3 with storage integration (recommended approach)
CREATE STAGE s3_with_integration
    URL = 's3://my-bucket/data/'
    STORAGE_INTEGRATION = my_s3_integration;
-- S3 with IAM credentials (temporary)
CREATE STAGE s3_with_iam_temp
    URL = 's3://my-bucket/staging/'
    CREDENTIALS = (
    AWS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'
    AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    AWS_TOKEN = 'temporary-session-token'
  );
-- S3 with IAM role
CREATE STAGE s3_with_iam_role
    URL = 's3://my-bucket/warehouse/'
    CREDENTIALS = (
    AWS_ROLE = 'arn:aws:iam::123456789012:role/MySnowflakeRole'
  );
-- S3 with client-side encryption (AWS_CSE)
CREATE STAGE s3_client_side_enc
    URL = 's3://encrypted-bucket/data/'
    STORAGE_INTEGRATION = my_s3_int
    ENCRYPTION = (
    TYPE = 'AWS_CSE'
    MASTER_KEY = 'base64EncodedKey=='
  );
-- S3 with server-side encryption (AWS_SSE_KMS)
CREATE STAGE s3_kms_encryption
    URL = 's3://kms-bucket/data/'
    STORAGE_INTEGRATION = my_s3_int
    ENCRYPTION = (
    TYPE = 'AWS_SSE_KMS'
    KMS_KEY_ID = 'aws/snowflake'
  );
-- S3 in China region
CREATE STAGE s3_china
    URL = 's3china://cn-bucket/data/'
    STORAGE_INTEGRATION = china_integration;
-- S3 in government region
CREATE STAGE s3_gov
    URL = 's3gov://gov-bucket/data/'
    CREDENTIALS = (
    AWS_KEY_ID = 'AKIA...'
    AWS_SECRET_KEY = 'secret...'
  );
-- S3 with directory table and auto-refresh
CREATE STAGE s3_with_directory
    URL = 's3://my-bucket/streaming/'
    STORAGE_INTEGRATION = my_s3_int
    DIRECTORY = (
    ENABLE = TRUE
    REFRESH_ON_CREATE = TRUE
    AUTO_REFRESH = TRUE
  );
-- ============================================================================
-- EXTERNAL STAGES - GOOGLE CLOUD STORAGE
-- ============================================================================
-- GCS with storage integration
CREATE STAGE gcs_basic
    URL = 'gcs://my-gcs-bucket/data/'
    STORAGE_INTEGRATION = my_gcs_integration;
-- GCS with KMS encryption
CREATE STAGE gcs_kms
    URL = 'gcs://encrypted-bucket/data/'
    STORAGE_INTEGRATION = my_gcs_int
    ENCRYPTION = (
    TYPE = 'GCS_SSE_KMS'
    KMS_KEY_ID = 'projects/myproject/locations/us/keyRings/myring/cryptoKeys/mykey'
  );
-- GCS with directory and notification integration
CREATE STAGE gcs_with_notifications
    URL = 'gcs://streaming-bucket/events/'
    STORAGE_INTEGRATION = my_gcs_int
    DIRECTORY = (
    ENABLE = TRUE
    AUTO_REFRESH = TRUE
    NOTIFICATION_INTEGRATION = 'my_pubsub_integration'
  );
-- ============================================================================
-- EXTERNAL STAGES - MICROSOFT AZURE
-- ============================================================================
-- Azure with storage integration
CREATE STAGE azure_basic
    URL = 'azure://myaccount.blob.core.windows.net/mycontainer/data/'
    STORAGE_INTEGRATION = my_azure_integration;
-- Azure with SAS token credentials
CREATE STAGE azure_sas
    URL = 'azure://myaccount.blob.core.windows.net/private-container/data/'
    CREDENTIALS = (
    AZURE_SAS_TOKEN = '?sv=2020-08-04&ss=bfqt&srt=sco&sp=rwdlacupitfx&se=2024-12-31T23:59:59Z&st=2024-01-01T00:00:00Z&spr=https&sig=signature...'
  );
-- Azure with client-side encryption
CREATE STAGE azure_encrypted
    URL = 'azure://secure.blob.core.windows.net/encrypted/data/'
    STORAGE_INTEGRATION = my_azure_int
    ENCRYPTION = (
    TYPE = 'AZURE_CSE'
    MASTER_KEY = 'base64EncodedAzureKey=='
  );
-- Azure with directory and event notifications
CREATE STAGE azure_events
    URL = 'azure://events.blob.core.windows.net/streaming/data/'
    STORAGE_INTEGRATION = my_azure_int
    DIRECTORY = (
    ENABLE = TRUE
    AUTO_REFRESH = TRUE
    NOTIFICATION_INTEGRATION = 'my_event_grid_integration'
  );
-- ============================================================================
-- S3-COMPATIBLE STORAGE (MinIO, etc.)
-- ============================================================================
-- S3-compatible with custom endpoint
CREATE STAGE s3_compatible
    URL = 's3compat://my-bucket/data/'
    ENDPOINT = 'https://minio.example.com:9000'
    CREDENTIALS = (
    AWS_KEY_ID = 'minioadmin'
    AWS_SECRET_KEY = 'minioadmin'
  );
-- ============================================================================
-- FILE FORMATS
-- ============================================================================
-- Stage with named file format
CREATE STAGE with_named_format
    URL = 's3://data/csv/'
    STORAGE_INTEGRATION = my_int
    FILE_FORMAT = (FORMAT_NAME = 'my_csv_format');
-- Stage with inline CSV format
CREATE STAGE csv_inline
    FILE_FORMAT = (
    TYPE = CSV
    COMPRESSION = GZIP
    FIELD_DELIMITER = '|'
    SKIP_HEADER = 1
    NULL_IF = ('NULL', '\\N')
  );
-- Stage with JSON format
CREATE STAGE json_stage
    FILE_FORMAT = (
    TYPE = JSON
    COMPRESSION = AUTO
    STRIP_OUTER_ARRAY = TRUE
    STRIP_NULL_VALUES = TRUE
  );
-- Stage with Parquet format
CREATE STAGE parquet_stage
    FILE_FORMAT = (
    TYPE = PARQUET
    COMPRESSION = SNAPPY
    BINARY_AS_TEXT = FALSE
  );
-- ============================================================================
-- MODIFIERS AND OPTIONS
-- ============================================================================
-- OR REPLACE modifier
CREATE OR REPLACE STAGE replaceable_stage
    URL = 's3://bucket/path/'
    STORAGE_INTEGRATION = my_int;
-- TEMPORARY stage
CREATE TEMPORARY STAGE temp_stage;
-- IF NOT EXISTS
CREATE STAGE IF NOT EXISTS safe_create;
-- All modifiers combined
CREATE OR REPLACE TEMPORARY STAGE IF NOT EXISTS full_modifiers
    URL = 's3://bucket/'
    STORAGE_INTEGRATION = my_int;
-- With COMMENT
CREATE STAGE documented_stage
    URL = 's3://data/'
    STORAGE_INTEGRATION = my_int
    COMMENT = 'Production data loading stage for customer records';
-- CLONE an existing stage
CREATE STAGE cloned_stage
    CLONE production_stage;
-- ============================================================================
-- COMPREHENSIVE EXAMPLE
-- ============================================================================
CREATE OR REPLACE TEMPORARY STAGE IF NOT EXISTS production_loader
    URL = 's3://company-data-warehouse/ingest/customers/'
    STORAGE_INTEGRATION = prod_aws_integration
    ENCRYPTION = (
    TYPE = 'AWS_SSE_KMS'
    KMS_KEY_ID = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
  )
    DIRECTORY = (
    ENABLE = TRUE
    REFRESH_ON_CREATE = TRUE
    AUTO_REFRESH = TRUE
  )
    FILE_FORMAT = (
    TYPE = PARQUET
    COMPRESSION = SNAPPY
    BINARY_AS_TEXT = FALSE
    TRIM_SPACE = TRUE
  )
    COMMENT = 'Automated customer data ingestion stage with KMS encryption and auto-refresh directory table';