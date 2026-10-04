-- Hostile trivia test: PIVOT with single aggregation (Snowflake does NOT support multiple aggregations in one PIVOT)
SELECT /* outer */ * /* star */ 
FROM /* before FROM */ (
    SELECT /* inner select */ 
        region /* col1 */ , /* comma1 */ 
        product /* col2 */ , /* comma2 */ 
        sales /* col3 */ 
    FROM /* inner FROM */ sales_data /* table */ 
) /* close subquery */ PIVOT /* keyword */ ( /* open pivot */ SUM /* agg */ ( /* open */ sales /* col */ ) /* close */ AS /* alias */ total_sales /* alias1 */ FOR /* before FOR */ product /* pivot col */ IN /* before IN */ ( /* open list */ /* before first */ 'Widget' /* val1 */ AS /* alias */ widget /* alias1 */ , /* comma */ /* before second */ 'Gadget' /* val2 */ AS /* alias */ gadget /* alias2 */ , /* comma */ /* before third */ 'Doohickey' /* val3 */ AS /* alias */ doohickey /* alias3 */ )) /* close list */ /* close pivot */ AS /* before alias */ pivoted /* alias */ ;