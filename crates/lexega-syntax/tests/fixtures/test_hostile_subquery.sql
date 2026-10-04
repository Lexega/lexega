-- Hostile trivia test: Correlated subqueries in various positions
SELECT /* outer select */ 
    o /* alias */ . /* dot */ id /* col1 */ , /* comma */ 
    o /* alias */ . /* dot */ customer_id /* col2 */ , /* comma */ 
    ( /* open scalar subquery */ SELECT /* scalar select */ -- scalar comment
    MAX /* agg */ ( /* open */ oi /* inner alias */ . /* dot */ price /* col */ ) /* close */ 
    FROM /* scalar FROM */ order_items /* table */ oi /* alias */ 
    WHERE /* scalar WHERE */ oi /* alias */ . /* dot */ order_id /* col */ = /* equals */ o /* outer ref */ . /* dot */ id /* col */ ) /* close scalar subquery */ AS /* alias kw */ max_price /* alias */ , /* comma */ 
    ( /* open exists */ SELECT /* exists select */ COUNT /* agg */ ( /* open */ * /* star */ ) /* close */ 
    FROM /* exists FROM */ payments /* table */ p /* alias */ 
    WHERE /* exists WHERE */ p /* alias */ . /* dot */ order_id /* col */ = /* equals */ o /* outer ref */ . /* dot */ id /* col */ AND /* and */ p /* alias */ . /* dot */ status /* col */ = /* equals */ 'completed' /* val */ ) /* close exists */ AS /* alias kw */ payment_count /* alias */ 
FROM /* outer FROM */ orders /* table */ o /* alias */ 
WHERE /* outer WHERE */ o /* alias */ . /* dot */ total /* col */ > /* gt */ ( /* open subquery */ SELECT /* avg select */ AVG /* agg */ ( /* open */ total /* col */ ) /* close */ 
FROM /* avg FROM */ orders /* table */ 
WHERE /* avg WHERE */ status /* col */ = /* equals */ 'completed' /* val */ ) /* close subquery */ AND /* and */ EXISTS /* exists */ ( /* open exists */ 
    SELECT /* exists select */ 1 /* literal */ 
    FROM /* exists FROM */ customers /* table */ c /* alias */ 
    WHERE /* exists WHERE */ c /* alias */ . /* dot */ id /* col */ = /* equals */ o /* outer ref */ . /* dot */ customer_id /* col */ AND /* and */ c /* alias */ . /* dot */ vip /* col */ = /* equals */ TRUE /* bool */ 
) /* close exists */ ;