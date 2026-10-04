-- Comprehensive SESSION POLICY test fixture
-- Tests all CREATE, ALTER, and DROP variants with multi-statement script
-- CREATE SESSION POLICY with all properties
CREATE SESSION POLICY comprehensive_policy
  SESSION_IDLE_TIMEOUT_MINS = 720
  SESSION_UI_IDLE_TIMEOUT_MINS = 360
  ALLOWED_SECONDARY_ROLES = ('ANALYST', 'DEVELOPER', 'VIEWER')
  BLOCKED_SECONDARY_ROLES = ('ADMIN', 'SYSADMIN')
  COMMENT = 'Comprehensive test policy with all properties';
-- CREATE OR REPLACE with minimal properties
CREATE OR REPLACE SESSION POLICY minimal_policy
  SESSION_IDLE_TIMEOUT_MINS = 30;
-- CREATE IF NOT EXISTS with role restrictions
CREATE SESSION POLICY IF NOT EXISTS role_restricted_policy
  ALLOWED_SECONDARY_ROLES = ('ROLE1')
  BLOCKED_SECONDARY_ROLES = ('ROLE2', 'ROLE3');
-- ALTER SESSION POLICY - RENAME
ALTER SESSION POLICY old_policy RENAME TO renamed_policy;
-- ALTER SESSION POLICY IF EXISTS - SET timeout
ALTER SESSION POLICY IF EXISTS comprehensive_policy SET
  SESSION_IDLE_TIMEOUT_MINS = 1440;
-- ALTER SESSION POLICY - SET multiple properties
ALTER SESSION POLICY comprehensive_policy SET
  SESSION_IDLE_TIMEOUT_MINS = 480
  SESSION_UI_IDLE_TIMEOUT_MINS = 240
  ALLOWED_SECONDARY_ROLES = ('DATA_ENGINEER', 'ANALYST')
  BLOCKED_SECONDARY_ROLES = ('GUEST')
  COMMENT = 'Updated comprehensive policy';
-- ALTER SESSION POLICY - SET TAG
ALTER SESSION POLICY comprehensive_policy SET TAG
  owner = 'data_team',
  cost_center = 'engineering',
  environment = 'production';
-- ALTER SESSION POLICY - UNSET individual properties
ALTER SESSION POLICY minimal_policy UNSET SESSION_UI_IDLE_TIMEOUT_MINS;
-- ALTER SESSION POLICY - UNSET multiple properties
ALTER SESSION POLICY comprehensive_policy UNSET
  ALLOWED_SECONDARY_ROLES
  BLOCKED_SECONDARY_ROLES
  COMMENT;
-- ALTER SESSION POLICY - UNSET TAG
ALTER SESSION POLICY comprehensive_policy UNSET TAG owner, cost_center;
-- DROP SESSION POLICY
DROP SESSION POLICY minimal_policy;
-- DROP SESSION POLICY IF EXISTS
DROP SESSION POLICY IF EXISTS old_policy;
-- Multi-statement governance scenario
CREATE SESSION POLICY security_policy
  SESSION_IDLE_TIMEOUT_MINS = 15
  SESSION_UI_IDLE_TIMEOUT_MINS = 10
  BLOCKED_SECONDARY_ROLES = ('PUBLIC', 'GUEST')
  COMMENT = 'High-security policy with strict timeouts';
ALTER SESSION POLICY security_policy SET TAG security_level = 'high';
-- Edge case: empty role lists
CREATE SESSION POLICY empty_roles_policy
  ALLOWED_SECONDARY_ROLES = ()
  BLOCKED_SECONDARY_ROLES = ();
-- Edge case: very long timeout (potential security risk)
CREATE SESSION POLICY long_timeout_policy
  SESSION_IDLE_TIMEOUT_MINS = 2880
  SESSION_UI_IDLE_TIMEOUT_MINS = 1440;
DROP SESSION POLICY IF EXISTS security_policy;