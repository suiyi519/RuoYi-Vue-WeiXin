
-- 2024/2/26
ALTER TABLE sys_user ADD open_id varchar(100) NULL COMMENT '微信open_id';
ALTER TABLE sys_user CHANGE open_id open_id varchar(100) NULL COMMENT '微信open_id' AFTER update_time;
ALTER TABLE sys_user ADD union_id varchar(100) NULL COMMENT '微信union_id';
ALTER TABLE sys_user CHANGE union_id union_id varchar(100) NULL COMMENT '微信union_id' AFTER open_id;
