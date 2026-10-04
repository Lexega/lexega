-- Simple test to debug parser
CREATE STAGE my_dir_stage
    DIRECTORY = (ENABLE = TRUE)
    FILE_FORMAT = (TYPE = CSV);