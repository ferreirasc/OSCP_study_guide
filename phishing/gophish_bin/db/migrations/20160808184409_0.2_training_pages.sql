
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE IF NOT EXISTS "training_pages" ("id" integer primary key autoincrement,"user_id" bigint,"name" varchar(255),"html" varchar(255),"modified_date" datetime );

ALTER TABLE "campaigns" ADD COLUMN "training_page_id" bigint;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
DROP TABLE "training_pages"
