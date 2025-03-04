DROP TABLE `User`;

----

CREATE TABLE `User` (
  `userID` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL, 
  `password` TEXT NOT NULL,
  `createdAt` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updatedAt` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`userID`),
  UNIQUE (`email`)
);


----

ALTER TABLE `User` ADD `firstName` TEXT NOT NULL;

----

ALTER TABLE `User` ADD `lastName` TEXT NOT NULL;
