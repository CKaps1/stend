DROP TABLE IF EXISTS users CASCADE;
CREATE TABLE users(
	userid bigserial primary key,
	email bytea unique not null,
	emailnonce bytea unique not null,
	emailsearchable bytea unique not null,
	lastlogin date,
	username text unique not null,
	passwordhash bytea unique not null,
	passwordsalt bytea unique not null,
	gender bit(8),
	profilepicture bytea,
	profilepictureurl text,
	birthyear integer,
	permanentlocation bytea,
	permanentlocationnonce bytea unique,
	displayname text,
	incorrect_password_attempts integer,
	incorrect_password_attempt_date date
);

DROP TABLE IF EXISTS sessions CASCADE;
CREATE TABLE sessions(
	sessionid bigserial primary key,
	userid bigint not null,
	refreshkeyhash bytea unique not null,
	refreshkeysalt bytea unique not null,
	expirydate date not null,
	FOREIGN KEY (userid) REFERENCES users(userid)
);


DROP TABLE IF EXISTS content CASCADE;
CREATE TABLE content(
	contentId bigserial primary key,
	fileName text unique not null,
	owner bigint not null,
	displayname text,
	caption text,
	likes bigint not null,
	dislikes bigint not null,
	views bigint not null,
	flags bigint not null,
	displayname_tsvector text,
	caption_tsvector text,
	isPublic bit(1),
	canComment bit(1),
	FOREIGN KEY(owner) REFERENCES users(userId)
);

DROP TABLE IF EXISTS ACL CASCADE;
CREATE TABLE ACL(
	ACLId bigserial primary key,
	contentId bigint not null,
	userId bigint not null,
	permission smallint not null,
	owner bigint not null,
	FOREIGN KEY(contentId) REFERENCES content(contentId),
	FOREIGN KEY(userId) REFERENCES users(userId),
	FOREIGN KEY(owner) REFERENCES users(userId)
);

DROP TABLE IF EXISTS comments CASCADE;
CREATE TABLE comments(
	commentId bigserial primary key,
	userId bigint not null,
	contentId bigint not null,
	upvotes int not null,
	downvotes int not null,
	comment text not null,

	FOREIGN KEY (userId) REFERENCES users(userId),
	FOREIGN KEY (contentId) REFERENCES content(contentId)
);

DROP TABLE IF EXISTS votes CASCADE;
CREATE TABLE votes(
	voteId bigserial primary key,
	commentId bigint not null,
	userid bigint not null,
	vote bit(1) not null,
	FOREIGN KEY (userId) REFERENCES users(userId),
	FOREIGN KEY (commentId) REFERENCES comments(commentId)
);

DROP TABLE IF EXISTS Tags CASCADE;
CREATE TABLE tags(
	tagId bigserial primary key,
	name text unique not null
);

DROP TABLE IF EXISTS tagAssociations CASCADE;
CREATE TABLE tagAssociations(
	assocId bigserial primary key,
	tagId bigint not null,
	contentId bigint not null,

	FOREIGN KEY (tagId) REFERENCES tags(tagId),
	FOREIGN KEY (contentId) REFERENCES content(contentId)
);

