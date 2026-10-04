-- Test CREATE STAGE parsing
-- Internal stage (simple)
CREATE STAGE my_internal_stage;
-- Internal stage with encryption
CREATE STAGE my_secure_stage
    ENCRYPTION = (TYPE = 'SNOWFLAKE_FULL');
-- Internal stage with directory table
CREATE STAGE my_dir_stage
    DIRECTORY = (ENABLE = TRUE AUTO_REFRESH = TRUE)
    FILE_FORMAT = (TYPE = CSV);
-- External stage (S3)
CREATE STAGE my_s3_stage
    URL = 's3://mybucket/path/'
    STORAGE_INTEGRATION = my_s3_int
    FILE_FORMAT = (TYPE = PARQUET);
-- External stage with credentials
CREATE STAGE my_s3_cred_stage
    URL = 's3://mybucket/data/'
    CREDENTIALS = (
    AWS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'
    AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
  )
    ENCRYPTION = (TYPE = 'AWS_SSE_KMS' KMS_KEY_ID = 'aws/key');
-- External stage (GCS)
CREATE OR REPLACE STAGE my_gcs_stage
    URL = 'gcs://mybucket/path/'
    STORAGE_INTEGRATION = my_gcs_int
    DIRECTORY = (
    ENABLE = TRUE
    AUTO_REFRESH = TRUE
    NOTIFICATION_INTEGRATION = 'my_gcs_notification'
  );
-- External stage (Azure)
CREATE TEMPORARY STAGE my_azure_stage
    URL = 'azure://myaccount.blob.core.windows.net/mycontainer/path/'
    CREDENTIALS = (AZURE_SAS_TOKEN = '?sv=2016-05-31&ss=b')
    ENCRYPTION = (TYPE = 'AZURE_CSE' MASTER_KEY = 'key123')
    FILE_FORMAT = (FORMAT_NAME = 'my_csv_format');
-- Stage with all options
CREATE OR REPLACE TEMPORARY STAGE IF NOT EXISTS my_full_stage
    URL = 's3://data-bucket/warehouse/'
    STORAGE_INTEGRATION = prod_s3_integration
    ENCRYPTION = (TYPE = 'AWS_SSE_S3')
    DIRECTORY = (
    ENABLE = TRUE
    REFRESH_ON_CREATE = TRUE
    AUTO_REFRESH = TRUE
  )
    FILE_FORMAT = (
    TYPE = JSON
    COMPRESSION = GZIP
    STRIP_OUTER_ARRAY = TRUE
  )
    COMMENT = 'Production data warehouse stage';
-- S3-compatible storage
CREATE STAGE my_s3compat_stage
    URL = 's3compat://mybucket/path/'
    ENDPOINT = 'https://minio.example.com:9000'
    CREDENTIALS = (
    AWS_KEY_ID = 'minioadmin'
    AWS_SECRET_KEY = 'minioadmin'
  );
-- Stage with clone
CREATE STAGE my_cloned_stage
    CLONE my_s3_stage;
-- Stage with comment
CREATE STAGE my_commented_stage
    COMMENT = 'This is a test stage for data loading';