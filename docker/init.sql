CREATE EXTENSION IF NOT EXISTS pgcrypto;

create table role(
	id UUID primary key default gen_random_uuid(),
	name text constraint unique_name unique not null
	);

create table users(
	uid UUID primary key default gen_random_uuid(),
	login text constraint unique_login unique not null,
	email text constraint unique_email unique not null,
	password text not null,
	roleId UUID not null references role(id)
	);
	
create table sessions(
    sessionId UUID primary key default gen_random_uuid(),
    uid UUID not null references users(uid) on delete cascade,
    exp bigint not null
	);

insert into role(name)
values ('admin'),
	('moderator'),
	('user');
