-- Test CLUSTER BY comment duplication
CREATE TABLE t (
    id INTEGER,
    PRIMARY KEY (id) /* after close pk */ 
) /* after columns */ 
CLUSTER /* after CLUSTER */ BY /* after BY */ (id) /* cluster end */ ;