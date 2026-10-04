-- Comprehensive CREATE STAGE test cases
-- 1. Simple internal stage
CREATE STAGE my_int_stage;
-- 2. Internal stage with encryption
CREATE STAGE my_secure_stage
    ENCRYPTION = (TYPE = 'SNOWFLAKE_FULL');
-- 3. Temporary internal stage with directory table
CREATE TEMPORARY STAGE my_temp_stage
    DIRECTORY = (ENABLE = TRUE AUTO_REFRESH = FALSE)
    FILE_FORMAT = (TYPE = CSV);
-- 4. External S3 stage with storage integration
CREATE STAGE my_s3_stage
    URL = 's3://mybucket/path/'
    STORAGE_INTEGRATION = my_s3_int;
-- 5. External stage with credentials
CREATE OR REPLACE STAGE my_cred_stage
    URL = 's3://bucket/files/'
    CREDENTIALS = (AWS_KEY_ID = '1a2b3c' AWS_SECRET_KEY = '4x5y6z');
-- 6. External stage with encryption
CREATE STAGE my_encrypted_stage
    URL = 's3://encrypted/data/'
    STORAGE_INTEGRATION = my_int
    ENCRYPTION = (TYPE = 'AWS_SSE_KMS' KMS_KEY_ID = 'aws/key');
-- 7. External stage with directory table and file format
CREATE STAGE my_full_stage
    URL = 's3://load/files/'
    STORAGE_INTEGRATION = my_storage_int
    DIRECTORY = (ENABLE = TRUE AUTO_REFRESH = TRUE)
    FILE_FORMAT = (FORMAT_NAME = 'my_csv_format')
    COMMENT = 'Production data loading stage';
-- 8. Azure stage
CREATE STAGE my_azure_stage
    URL = 'azure://myaccount.blob.core.windows.net/container/path/'
    STORAGE_INTEGRATION = my_azure_int
    ENCRYPTION = (TYPE = 'AZURE_CSE' MASTER_KEY = 'key123');
-- 9. GCS stage
CREATE STAGE my_gcs_stage
    URL = 'gcs://mybucket/path/'
    STORAGE_INTEGRATION = my_gcs_int
    DIRECTORY = (ENABLE = TRUE NOTIFICATION_INTEGRATION = 'my_notification');
-- 10. IF NOT EXISTS variant
CREATE STAGE IF NOT EXISTS safe_stage
    URL = 's3://bucket/'
    STORAGE_INTEGRATION = my_int;
-- 11. Stage with file format type options
CREATE STAGE my_format_stage
    URL = 's3://data/'
    STORAGE_INTEGRATION = my_int
    FILE_FORMAT = (TYPE = JSON COMPRESSION = AUTO STRIP_OUTER_ARRAY = TRUE);
-- 12. Clone variant
CREATE STAGE new_stage
    CLONE existing_stage;