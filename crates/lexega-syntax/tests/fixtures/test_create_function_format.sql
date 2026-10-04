CREATE OR REPLACE FUNCTION my_udf(input_val FLOAT)
RETURNS FLOAT
LANGUAGE JAVASCRIPT
COMMENT = 'My UDF comment'
AS
$$
    if (INPUT_VAL === null) {
        return null;
    }
    return INPUT_VAL * 2.0;
$$;