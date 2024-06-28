CREATE TABLE IF NOT EXISTS "urls" (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    key TEXT NOT NULL UNIQUE
);

INSERT INTO urls (url, key) VALUES
("https://a-very-long-url.com", "shoRtkl9187ds");
