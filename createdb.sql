-- TODO: indexes

CREATE TABLE users
(
  id BIGSERIAL PRIMARY KEY NOT NULL,
  external_id TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMP WITH TIME ZONE,
  updated_at TIMESTAMP WITH TIME ZONE,
  deleted_at TIMESTAMP WITH TIME ZONE,
  email TEXT NOT NULL DEFAULT '',
  email_confirmed BOOLEAN NOT NULL DEFAULT false,
  password_hash TEXT NOT NULL,
  name TEXT NOT NULL,
  avatar_url TEXT NOT NULL DEFAULT '',
  eth_address TEXT NOT NULL
);

CREATE TABLE project_categories
(
  id BIGSERIAL NOT NULL PRIMARY KEY,
  name TEXT NOT NULL
);

CREATE TABLE countries
(
  id BIGSERIAL NOT NULL PRIMARY KEY,
  name TEXT NOT NULL
);

CREATE TABLE cities
(
  id BIGSERIAL NOT NULL PRIMARY KEY,
  country_id BIGINT NOT NULL REFERENCES countries(id),
  name TEXT NOT NULL
);

CREATE TABLE projects
(
  id BIGSERIAL NOT NULL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users (id),

  created_at TIMESTAMP WITH TIME ZONE NOT NULL,

  status TEXT NOT NULL,

  moderation_status TEXT NOT NULL,
  moderation_failure_message TEXT NOT NULL DEFAULT '',

  goal DECIMAL NOT NULL,
  duration INT NOT NULL,

  category_id BIGINT NOT NULL REFERENCES project_categories(id),
  city_id BIGINT NOT NULL REFERENCES cities(id),

  title TEXT NOT NULL DEFAULT '',
  short_description TEXT NOT NULL DEFAULT '',
  full_description TEXT NOT NULL DEFAULT '',
  cover_url TEXT NOT NULL DEFAULT '',
  video_url TEXT NOT NULL DEFAULT '',
  facebook_url TEXT NOT NULL DEFAULT '',
  twitter_url TEXT NOT NULL DEFAULT '',

  eth_address TEXT NOT NULL
);

CREATE TABLE user_password_resets (
  user_id BIGINT NOT NULL REFERENCES users (id),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  code TEXT NOT NULL
);

CREATE TABLE user_email_confirmations (
  user_id BIGINT NOT NULL REFERENCES users (id),
  code TEXT NOT NULL,
  email TEXT NOT NULL
);

CREATE TABLE user_kycs (
  user_id BIGINT NOT NULL REFERENCES users (id),
  eth_address TEXT NOT NULL,
  full_name TEXT NOT NULL,
  date_of_birth TEXT NOT NULL,
  place_of_birth TEXT NOT NULL,
  place_of_residence TEXT NOT NULL,
  country_of_residence TEXT NOT NULL,
  phone TEXT NOT NULL,
  status TEXT NOT NULL,
  doc1_file_name TEXT NOT NULL,
  doc2_file_name TEXT NOT NULL,
  failure_message TEXT NOT NULL DEFAULT ''
);

CREATE TABLE user_mining_credentials (
  user_id BIGINT NOT NULL REFERENCES users (id),
  login TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL DEFAULT ''
);

CREATE TABLE user_mining_projects (
  user_id BIGINT NOT NULL REFERENCES users (id),
  project_id BIGINT NOT NULL REFERENCES projects (id),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE user_withdraws (
  user_id BIGINT NOT NULL REFERENCES users (id),
  status TEXT NOT NULL,
  amount TEXT NOT NULL
);



------------------------------------------------------------------------------------------------------------------------

CREATE TABLE shares
(
  projectid BIGSERIAL NOT NULL REFERENCES projects (id),
  poolid TEXT NOT NULL,
  blockheight BIGINT NOT NULL,
  difficulty DOUBLE PRECISION NOT NULL,
  networkdifficulty DOUBLE PRECISION NOT NULL,
  miner TEXT NOT NULL,
  worker TEXT NULL,
  useragent TEXT NULL,
  ipaddress TEXT NOT NULL,
  source TEXT NULL,
  created TIMESTAMP NOT NULL
);

CREATE INDEX IDX_SHARES_POOL_MINER on shares(poolid, miner);
CREATE INDEX IDX_SHARES_POOL_CREATED ON shares(poolid, created);
CREATE INDEX IDX_SHARES_POOL_MINER_DIFFICULTY on shares(poolid, miner, difficulty);

CREATE TABLE blocks
(
  id BIGSERIAL NOT NULL PRIMARY KEY,
  projectid BIGINT NOT NULL REFERENCES projects (id),
  poolid TEXT NOT NULL,
  blockheight BIGINT NOT NULL,
  networkdifficulty DOUBLE PRECISION NOT NULL,
  status TEXT NOT NULL,
  type TEXT NULL,
  confirmationprogress FLOAT NOT NULL DEFAULT 0,
  effort FLOAT NULL,
  transactionconfirmationdata TEXT NOT NULL,
  miner TEXT NULL,
  reward decimal(28,12) NULL,
  source TEXT NULL,
  hash TEXT NULL,
  created TIMESTAMP NOT NULL,

  CONSTRAINT BLOCKS_POOL_HEIGHT UNIQUE (projectid, poolid, blockheight, type) DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX IDX_BLOCKS_POOL_BLOCK_STATUS on blocks(poolid, blockheight, status);

CREATE TABLE balances
(
  projectid BIGINT NOT NULL REFERENCES projects (id),
  poolid TEXT NOT NULL,
  address TEXT NOT NULL,
  amount decimal(28,12) NOT NULL DEFAULT 0,
  created TIMESTAMP NOT NULL,
  updated TIMESTAMP NOT NULL,

  primary key(projectid, poolid, address)
);

CREATE TABLE balance_changes
(
  id BIGSERIAL NOT NULL PRIMARY KEY,
  projectid BIGINT NOT NULL REFERENCES projects (id),
  poolid TEXT NOT NULL,
  address TEXT NOT NULL,
  amount decimal(28,12) NOT NULL DEFAULT 0,
  usage TEXT NULL,
  created TIMESTAMP NOT NULL
);

CREATE INDEX IDX_BALANCE_CHANGES_POOL_ADDRESS_CREATED on balance_changes(poolid, address, created desc);

CREATE TABLE payments
(
  id BIGSERIAL NOT NULL PRIMARY KEY,
  poolid TEXT NOT NULL,
  coin TEXT NOT NULL,
  address TEXT NOT NULL,
  amount decimal(28,12) NOT NULL,
  transactionconfirmationdata TEXT NOT NULL,
  created TIMESTAMP NOT NULL
);

CREATE INDEX IDX_PAYMENTS_POOL_COIN_WALLET on payments(poolid, coin, address);

CREATE TABLE poolstats
(
  id BIGSERIAL NOT NULL PRIMARY KEY,
  poolid TEXT NOT NULL,
  connectedminers INT NOT NULL DEFAULT 0,
  poolhashrate DOUBLE PRECISION NOT NULL DEFAULT 0,
  sharespersecond DOUBLE PRECISION NOT NULL DEFAULT 0,
  networkhashrate DOUBLE PRECISION NOT NULL DEFAULT 0,
  networkdifficulty DOUBLE PRECISION NOT NULL DEFAULT 0,
  lastnetworkblocktime TIMESTAMP NULL,
  blockheight BIGINT NOT NULL DEFAULT 0,
  connectedpeers INT NOT NULL DEFAULT 0,
  created TIMESTAMP NOT NULL
);

CREATE INDEX IDX_POOLSTATS_POOL_CREATED on poolstats(poolid, created);
CREATE INDEX IDX_POOLSTATS_POOL_CREATED_HOUR on poolstats(poolid, date_trunc('hour',created));

CREATE TABLE minerstats
(
  id BIGSERIAL NOT NULL PRIMARY KEY,
  poolid TEXT NOT NULL,
  miner TEXT NOT NULL,
  worker TEXT NOT NULL,
  hashrate DOUBLE PRECISION NOT NULL DEFAULT 0,
  sharespersecond DOUBLE PRECISION NOT NULL DEFAULT 0,
  created TIMESTAMP NOT NULL
);

CREATE INDEX IDX_MINERSTATS_POOL_CREATED on minerstats(poolid, created);
CREATE INDEX IDX_MINERSTATS_POOL_MINER_CREATED on minerstats(poolid, miner, created);
CREATE INDEX IDX_MINERSTATS_POOL_MINER_CREATED_HOUR on minerstats(poolid, miner, date_trunc('hour',created));
CREATE INDEX IDX_MINERSTATS_POOL_MINER_CREATED_DAY on minerstats(poolid, miner, date_trunc('day',created));
