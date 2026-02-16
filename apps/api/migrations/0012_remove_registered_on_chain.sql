-- Remove redundant registered_on_chain column
-- Column may not exist in fresh local databases, so this is a safe no-op select
SELECT 1;
