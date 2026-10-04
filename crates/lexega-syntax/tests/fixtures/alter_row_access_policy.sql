-- Basic RENAME TO
ALTER ROW ACCESS POLICY policy1 RENAME TO policy1_v2;
-- IF EXISTS variant
ALTER ROW ACCESS POLICY IF EXISTS policy2 RENAME TO policy2_new;
-- SET BODY with simple expression
ALTER ROW ACCESS POLICY access_control
SET BODY -> user_id = CURRENT_USER();
-- SET BODY with complex expression
ALTER ROW ACCESS POLICY department_policy
SET BODY -> dept IN ('HR', 'FINANCE') OR role = 'ADMIN';
-- SET TAG single
ALTER ROW ACCESS POLICY data_policy
SET TAG owner = 'data_team';
-- SET TAG multiple
ALTER ROW ACCESS POLICY sensitive_policy
SET TAG sensitivity = 'high', compliance = 'GDPR', owner = 'security_team';
-- UNSET TAG single
ALTER ROW ACCESS POLICY old_policy
UNSET TAG deprecated;
-- UNSET TAG multiple
ALTER ROW ACCESS POLICY cleanup_policy
UNSET TAG temp_tag, test_tag, old_metadata;
-- SET COMMENT
ALTER ROW ACCESS POLICY documented_policy
SET COMMENT = 'Updated to reflect new compliance requirements';
-- UNSET COMMENT
ALTER ROW ACCESS POLICY undocumented_policy
UNSET COMMENT;
-- Complex: IF EXISTS with SET BODY
ALTER ROW ACCESS POLICY IF EXISTS regional_access
SET BODY -> region = 'US-WEST' AND compliance_level >= 3;
-- Qualified name
ALTER ROW ACCESS POLICY mydb.myschema.my_policy
RENAME TO mydb.myschema.my_policy_v2;