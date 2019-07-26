create table users
(
    id      VARCHAR(250) not null
        primary key,
    name    VARCHAR(250) not null,
    email   VARCHAR(250) not null,
    picture VARCHAR(250)
);

create table category
(
    id      INTEGER      not null
        primary key,
    name    VARCHAR(250) not null,
    created TIMESTAMP,
    user_id VARCHAR(250)
        references users(id)
);

create table catalog_item
(
    name        VARCHAR(80) not null,
    id          INTEGER     not null
        primary key,
    description VARCHAR(250),
    created     TIMESTAMP,
    category_id INTEGER
        references category(id),
    user_id     VARCHAR(250)
        references users(id)
);

