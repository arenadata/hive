SELECT 'Upgrading MetaStore schema from 3.1.0 to 3.1.3';

-- HIVE-20221: change PARTITION_PARAMS.PARAM_VALUE to TEXT
alter table "PARTITION_PARAMS" alter column "PARAM_VALUE" type text using cast("PARAM_VALUE" as text);


-- These lines need to be last.  Insert any changes above.
UPDATE "VERSION" SET "SCHEMA_VERSION"='3.1.3', "VERSION_COMMENT"='Hive release version 3.1.3' where "VER_ID"=1;
SELECT 'Finished upgrading MetaStore schema from 3.1.0 to 3.1.3';
