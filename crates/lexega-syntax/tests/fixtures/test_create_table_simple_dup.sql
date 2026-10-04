-- Minimal repro for comment duplication in CREATE TABLE
CREATE TABLE my_table (
    id NUMBER
)
/* change tracking */ CHANGE_TRACKING /* ct kw */ = /* eq */ TRUE /* true */
/* data retention */ DATA_RETENTION_TIME_IN_DAYS /* drt kw */ = /* eq */ 7 /* seven */ ;