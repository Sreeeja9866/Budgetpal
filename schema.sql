CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  fullname TEXT NOT NULL,
  username TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL,
  security_question_1 TEXT,
  security_answer_1 TEXT,
  security_question_2 TEXT,
  security_answer_2 TEXT,
  incorrect_attempts INTEGER DEFAULT 0,
  lockout_time DATETIME,
  is_locked BOOLEAN DEFAULT 0
);