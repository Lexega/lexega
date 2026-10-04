CREATE STAGE my_s3_stage
    URL = 's3://mybucket/path/'
    STORAGE_INTEGRATION = my_s3_int;